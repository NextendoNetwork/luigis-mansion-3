package main

// Présence entre amis de Luigi's Mansion 3 (protocole 0x79, méthodes 13 / 14 / 15).
//
// Tout le mécanisme tient dans une capture du serveur de Nintendo, et il n'a rien
// à voir avec les notifications de MatchmakeExtension : sur la capture, la
// méthode 13 de MatchmakeExtension (types 101 à 104) renvoie zéro entrée, chez
// Nintendo comme chez nous. Ce n'est donc pas par là que passent les salons.
//
// Le vrai enchaînement, relevé sept fois sur sept dans la capture :
//
//	1. le joueur publie son état          C->S  0x79 méthode 13   (réponse VIDE)
//	2. le serveur prévient ses amis       S->C  0x0e méthode 1, type 128000,
//	                                            source = le PID du publieur
//	3. l'ami demande le détail            C->S  0x79 méthode 15 sur ce PID
//	4. le serveur rediffuse l'état        S->C  drapeaux + salon + pseudo
//
// L'étape 2 est la clé : le client n'a AUCUNE autre source pour les PID de ses
// amis, il les apprend par le champ « source » de la notification. Sans elle il
// n'appelle jamais la méthode 15 et l'écran « entre amis » reste vide — ce qui
// était exactement notre symptôme.
//
// Format publié en méthode 13 (79 octets) : u32 nombre d'entrées, puis par
// entrée une enveloppe {u8 0, u32 longueur} contenant {u8 clé, u16 longueur,
// données} — clé 0 = drapeaux d'état (u16), clé 1 = salon (u32), clé 2 = pseudo
// sur 44 octets. La réponse des méthodes 14/15 réutilise les mêmes clés.

import (
	"fmt"
	"sync"
	"time"

	nex "github.com/NextendoNetwork/nextendo-nex"
)

// friendStateNotifType est le type de notification que Nintendo pousse quand
// l'état d'un ami change. Relevé tel quel dans la capture (0x0001f400).
const friendStateNotifType uint32 = 128000

type friendState struct {
	flags uint16
	gid   uint32
	name  string
	at    time.Time
}

var (
	friendStateMu sync.RWMutex
	friendStates  = map[uint64]friendState{}
)

func getFriendState(pid uint64) (friendState, bool) {
	friendStateMu.RLock()
	defer friendStateMu.RUnlock()
	st, ok := friendStates[pid]
	return st, ok
}

func forgetFriendState(pid uint64) {
	friendStateMu.Lock()
	delete(friendStates, pid)
	friendStateMu.Unlock()
}

// parsePublishedState décode le corps de la méthode 13. Tolérant par choix : un
// corps inattendu ne doit pas faire échouer l'appel, seulement ne rien publier.
func parsePublishedState(body []byte) (friendState, bool) {
	le16 := func(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
	le32 := func(b []byte) uint32 {
		return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}

	if len(body) < 4 {
		return friendState{}, false
	}
	var st friendState
	got := false
	count := le32(body[:4])
	if count > 16 { // garde-fou : la capture en montre 3
		return friendState{}, false
	}
	pos := 4
	for i := uint32(0); i < count; i++ {
		if pos+5 > len(body) {
			break
		}
		pos++ // octet d'enveloppe, toujours 0 sur la capture
		length := int(le32(body[pos : pos+4]))
		pos += 4
		if length < 3 || pos+length > len(body) {
			break
		}
		entry := body[pos : pos+length]
		pos += length

		key := entry[0]
		dataLen := int(le16(entry[1:3]))
		if 3+dataLen > len(entry) {
			continue
		}
		data := entry[3 : 3+dataLen]
		switch key {
		case 0:
			if dataLen >= 2 {
				st.flags = le16(data)
				got = true
			}
		case 1:
			if dataLen >= 4 {
				st.gid = le32(data)
				got = true
			}
		case 2:
			st.name = trimNUL(data)
			got = true
		}
	}
	return st, got
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// publishFriendState enregistre l'état d'un joueur et, s'il a changé, prévient
// ses amis en ligne — l'étape que notre serveur ne faisait pas du tout.
func publishFriendState(pid uint64, st friendState, mm *nex.Matchmaking, ep *nex.Endpoint) {
	friendStateMu.Lock()
	prev, had := friendStates[pid]
	changed := !had || prev.flags != st.flags || prev.gid != st.gid || prev.name != st.name
	st.at = time.Now()
	friendStates[pid] = st
	friendStateMu.Unlock()

	if !changed || mm.FriendPIDs == nil {
		return
	}
	notified := 0
	for _, friend := range mm.FriendPIDs(pid) {
		target := ep.FindConnectionByPID(friend)
		if target == nil {
			continue // ami hors ligne : rien à pousser
		}
		nex.SendNotification(target, &nex.NotificationEvent{
			PIDSource: pid,
			Type:      friendStateNotifType,
		})
		notified++
	}
	if notified > 0 {
		fmt.Printf("[Friends] état pid=%d drapeaux=0x%04x salon=%d -> %d ami(s) prévenu(s)\n",
			pid, st.flags, st.gid, notified)
	}
}

// onlineFriendsWithState liste les amis du joueur qui ont publié un état : c'est
// ce que la méthode 14 renvoie à la connexion, avant que le client ne se mette à
// interroger la méthode 15.
func onlineFriendsWithState(mm *nex.Matchmaking, ep *nex.Endpoint, pid uint64) []uint64 {
	if mm.FriendPIDs == nil {
		return nil
	}
	var out []uint64
	for _, friend := range mm.FriendPIDs(pid) {
		if ep.FindConnectionByPID(friend) == nil {
			continue
		}
		if _, ok := getFriendState(friend); ok {
			out = append(out, friend)
		}
	}
	return out
}

package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Les octets ci-dessous proviennent d'une capture du serveur de Nintendo
// (Luigi's Mansion 3, protocole 0x79). Ils servent de référence : si l'encodage
// ou le décodage dérive, ces tests tombent.
//
// Les pseudonymes et l'identifiant de compte des joueurs capturés ont été
// remplacés par des valeurs neutres de MÊME longueur, pour ne pas publier les
// données personnelles de tiers. La structure, les drapeaux d'état et les
// identifiants de salon sont ceux de la capture, inchangés.

// decodePadded reconstitue un corps de méthode 13. Le décodeur de capture
// n'imprime que les 64 premiers octets alors que l'appel en fait 79 ; les 15
// manquants sont le remplissage à zéro du champ pseudo (fixé à 44 octets) plus
// un octet de queue que le serveur n'interprète pas.
func decodePadded(t *testing.T, s string, size int) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex invalide : %v", err)
	}
	if len(b) < size {
		b = append(b, make([]byte, size-len(b))...)
	}
	return b
}

func TestParsePublishedStateHorsSalon(t *testing.T) {
	// Capture, appel 18 : le joueur est en ligne mais n'a pas de salon.
	body := decodePadded(t, "0300000000050000000002000040000700000001040000000000"+
		"002f000000022c006a6f7565757200000000000000000000000000000000000000000000000000", 79)

	st, ok := parsePublishedState(body)
	if !ok {
		t.Fatal("le corps de la capture devrait être reconnu")
	}
	if st.flags != 0x4000 {
		t.Errorf("drapeaux = 0x%04x, attendu 0x4000", st.flags)
	}
	if st.gid != 0 {
		t.Errorf("salon = %d, attendu 0 (le joueur n'en a pas)", st.gid)
	}
	if st.name != "joueur" {
		t.Errorf("pseudo = %q, attendu \"joueur\"", st.name)
	}
}

func TestParsePublishedStateDansSalon(t *testing.T) {
	// Capture, appel 55 : le même joueur, cette fois dans le salon 0xbf2df6.
	body := decodePadded(t, "03000000000500000000020040720007000000010400f62dbf00"+
		"002f000000022c006a6f7565757200000000000000000000000000000000000000000000000000", 79)

	st, ok := parsePublishedState(body)
	if !ok {
		t.Fatal("le corps de la capture devrait être reconnu")
	}
	if st.flags != 0x7240 {
		t.Errorf("drapeaux = 0x%04x, attendu 0x7240", st.flags)
	}
	if st.gid != 0x00bf2df6 {
		t.Errorf("salon = 0x%08x, attendu 0x00bf2df6", st.gid)
	}
	if st.name != "joueur" {
		t.Errorf("pseudo = %q, attendu \"joueur\"", st.name)
	}
}

// TestEncodeFriendRecordsCapture vérifie que notre réponse reproduit exactement
// celle de Nintendo. Référence : capture, réponse à la méthode 15, appel 33 —
// un ami dans le salon 0xbf2df2. Le pseudo garde des caractères multi-octets
// (★☆) car le champ est de taille fixe et la troncature doit respecter les
// frontières de rune.
func TestEncodeFriendRecordsCapture(t *testing.T) {
	want, err := hex.DecodeString("0100000000470000001122334455667788030000000002004074010400f22dbf00022c00696e766974653635e29885e29886000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("hex invalide : %v", err)
	}

	got := encodeFriendRecords([]friendRecord{{
		pid:   0x8877665544332211,
		flags: 0x7440,
		gid:   0x00bf2df2,
		name:  "invite65★☆",
	}})

	if !bytes.Equal(got, want) {
		t.Errorf("réponse différente de celle de Nintendo\n produit (%d o) : %x\n attendu (%d o) : %x",
			len(got), got, len(want), want)
	}
}

// TestEncodeDecodeAllerRetour : ce qu'un joueur publie doit ressortir tel quel
// pour ses amis — c'est toute la logique du serveur sur ce protocole.
func TestEncodeDecodeAllerRetour(t *testing.T) {
	body := decodePadded(t, "03000000000500000000020040720007000000010400f62dbf00"+
		"002f000000022c006a6f7565757200000000000000000000000000000000000000000000000000", 79)
	st, ok := parsePublishedState(body)
	if !ok {
		t.Fatal("corps non reconnu")
	}

	enc := encodeFriendRecords([]friendRecord{{
		pid: 0x1234, flags: st.flags, gid: st.gid, name: st.name,
	}})
	if len(enc) != 80 {
		t.Fatalf("fiche de %d octets, attendu 80", len(enc))
	}
	// Disposition : 4 nombre de fiches, 1 état, 4 longueur, 8 pid, 4 nombre
	// d'entrées, puis {1 clé, 2 longueur, données}. Les drapeaux tombent donc en
	// 24 et le salon en 29.
	if flags := uint16(enc[24]) | uint16(enc[25])<<8; flags != 0x7240 {
		t.Errorf("drapeaux rediffusés = 0x%04x, attendu 0x7240", flags)
	}
	gid := uint32(enc[29]) | uint32(enc[30])<<8 | uint32(enc[31])<<16 | uint32(enc[32])<<24
	if gid != 0x00bf2df6 {
		t.Errorf("salon rediffusé = 0x%08x, attendu 0x00bf2df6", gid)
	}
}

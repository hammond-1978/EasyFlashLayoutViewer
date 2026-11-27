#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
flashmap.py - Mappa dettagliata dell'occupazione flash per dsPIC33 / PIC24
              (toolchain Microchip XC16 / XC-DSC), a partire da .map + .elf + .hex.

Uso:
    python flashmap.py  MioProgetto.X                 # cerca da solo map/elf/hex più recenti
    python flashmap.py  fw.map fw.elf fw.hex          # file espliciti, in qualsiasi ordine
    python flashmap.py  fw.map fw.elf fw.hex -o mappa.html --json mappa.json --lang en

Cosa usa di ciascun file:
    .map  (obbligatorio)  regioni di memoria, sezioni di output, sezioni di input
                          con il modulo (.o / libreria) di provenienza, opzioni del linker
    .elf  (consigliato)   elenco autorevole delle sezioni caricate in flash, indirizzi di
                          caricamento (LMA) e tabella simboli: funzioni static comprese
    .hex  (consigliato)   ciò che finisce davvero sul micro: verifica incrociata e
                          contenuti non descritti dal .map (bootloader, fill, ...)

Unità: gli indirizzi sono indirizzi PC (come nel .map e nel .gld). Ogni istruzione
occupa 2 unità PC e 3 byte di flash; nel .hex occupa 4 byte a indirizzo doppio.
Tutte le dimensioni in "byte" di questo report sono byte reali di flash (3 per parola).

Lingua: il report HTML contiene italiano, inglese e tedesco e si cambia dalla pagina;
--lang sceglie la lingua iniziale del report e quella dei messaggi a terminale.

Solo libreria standard, nessuna dipendenza. Python 3.7+.
"""
import argparse
import array
import collections
import datetime
import json
import os
import re
import struct
import sys

VERSION = "1.2"
LANGS = ("it", "en", "de")
LANG = "it"             # lingua dei messaggi a terminale (impostata da --lang)

# ----------------------------------------------------------------------------
# Categorie (l'ordine è anche l'ordine dei colori nel report)
# ----------------------------------------------------------------------------
CAT_IDS = ["code_app", "code_lib", "const", "dinit", "isr", "startup", "ivt", "config",
           "pad", "free", "reserved", "hexonly", "unmapped"]
CAT = {cid: i for i, cid in enumerate(CAT_IDS)}
USED_CATS = set(range(0, 9)) | {CAT["hexonly"]}

# codici negativi usati nell'array di proprietà delle parole
G_FREE, G_RESERVED, G_UNMAPPED, G_HEXONLY, G_HEX_IVT, G_HEX_CFG, G_HEX_RESET = -1, -2, -3, -4, -5, -6, -7
GAP_CAT = {
    G_FREE: CAT["free"], G_RESERVED: CAT["reserved"], G_UNMAPPED: CAT["unmapped"],
    G_HEXONLY: CAT["hexonly"], G_HEX_IVT: CAT["ivt"], G_HEX_CFG: CAT["config"],
    G_HEX_RESET: CAT["startup"],
}

RAM_REGION_NAMES = {"data", "ymemory", "xmemory", "eds", "dpsram", "auxdata", "sfrs", "ram"}
DEBUG_SECTION_RE = re.compile(
    r"^(\.debug|\.comment|\.stab|\.line|\.note|\.mdebug|\.gnu\.|__c30_signature|\.info\.|\.memory|\.symtab|\.strtab|\.shstrtab)")
LOCAL_LABEL_RE = re.compile(r"^(\.L|L\d+\^|\$)|\^")
PAGE = 0x800            # pagina di erase: 1024 istruzioni = 0x800 unità PC

# ----------------------------------------------------------------------------
# Testi in tre lingue: (italiano, inglese, tedesco)
# ----------------------------------------------------------------------------
MSG = {
    # categorie
    "cat_code_app": ("Codice applicazione", "Application code", "Anwendungscode"),
    "cat_code_lib": ("Librerie e runtime", "Libraries and runtime", "Bibliotheken und Laufzeit"),
    "cat_const": ("Costanti (.const / PSV)", "Constants (.const / PSV)", "Konstanten (.const / PSV)"),
    "cat_dinit": ("Init dati (.dinit)", "Data init (.dinit)", "Dateninitialisierung (.dinit)"),
    "cat_isr": ("ISR", "ISR", "ISR"),
    "cat_startup": ("Reset e startup", "Reset and startup", "Reset und Startup"),
    "cat_ivt": ("Vector table", "Vector table", "Vektortabelle"),
    "cat_config": ("Config word / altro", "Config words / other", "Config-Words / Sonstiges"),
    "cat_pad": ("Padding / fill", "Padding / fill", "Padding / Füllung"),
    "cat_free": ("Libero", "Free", "Frei"),
    "cat_reserved": ("Riservato non usato", "Reserved, unused", "Reserviert, ungenutzt"),
    "cat_hexonly": ("Solo nell'HEX (non nel .map)", "HEX only (not in the .map)", "Nur im HEX (nicht in der .map)"),
    "cat_unmapped": ("Fuori dalle regioni", "Outside the regions", "Außerhalb der Regionen"),

    # diagnostica
    "d_no_memcfg": (
        "Nel .map non ho trovato la tabella 'Memory Configuration': uso una sola regione fittizia.",
        "No 'Memory Configuration' table found in the .map: using a single dummy region.",
        "In der .map fehlt die Tabelle 'Memory Configuration': es wird eine einzige Ersatzregion verwendet."),
    "d_pc_bytes": (
        "Nel .map 1 unità PC = 1 byte (dsPIC33A / PIC32A?). Questo script assume parole da 24 bit (3 byte ogni 2 unità PC): le dimensioni in byte saranno sbagliate.",
        "In this .map 1 PC unit = 1 byte (dsPIC33A / PIC32A?). This script assumes 24-bit words (3 bytes per 2 PC units): byte sizes will be wrong.",
        "In dieser .map gilt 1 PC-Einheit = 1 Byte (dsPIC33A / PIC32A?). Das Skript geht von 24-Bit-Worten aus (3 Byte je 2 PC-Einheiten): die Byte-Größen stimmen dann nicht."),
    "d_elf_ratio": (
        "Rapporto inatteso tra dimensioni ELF e MAP ({ratio}): assumo 2 ottetti per unità PC.",
        "Unexpected ratio between ELF and MAP sizes ({ratio}): assuming 2 octets per PC unit.",
        "Unerwartetes Verhältnis zwischen ELF- und MAP-Größen ({ratio}): es werden 2 Oktette je PC-Einheit angenommen."),
    "d_elf_nomatch": (
        "Nessuna sezione dell'ELF coincide per nome e indirizzo con il .map: ELF e MAP sono della stessa build?",
        "No ELF section matches the .map by name and address: are ELF and MAP from the same build?",
        "Keine ELF-Sektion stimmt nach Name und Adresse mit der .map überein: stammen ELF und MAP aus demselben Build?"),
    "d_lma_diff": (
        "Sezione {name}: LMA da ELF {elf}, dal .map {map} (uso l'ELF).",
        "Section {name}: LMA from ELF {elf}, from the .map {map} (using the ELF).",
        "Sektion {name}: LMA laut ELF {elf}, laut .map {map} (ELF wird verwendet)."),
    "d_elf_missing": (
        "{n} sezioni del report 'program' del .map non sono nell'ELF (es. {name} @{addr}): ELF e MAP potrebbero essere di build diverse.",
        "{n} sections of the .map 'program' report are missing from the ELF (e.g. {name} @{addr}): ELF and MAP may come from different builds.",
        "{n} Sektionen aus dem 'program'-Report der .map fehlen im ELF (z. B. {name} @{addr}): ELF und MAP stammen möglicherweise aus verschiedenen Builds."),
    "d_no_elf": (
        "ELF non fornito: sezioni classificate dal solo .map; dei simboli vedo solo quelli globali e le loro dimensioni sono stime (distanza dal simbolo successivo, static incluse).",
        "No ELF given: sections are classified from the .map alone; only global symbols are visible and their sizes are estimates (distance to the next symbol, static functions included).",
        "Kein ELF angegeben: Sektionen werden nur anhand der .map klassifiziert; sichtbar sind nur globale Symbole, deren Größen geschätzt sind (Abstand zum nächsten Symbol, einschließlich static-Funktionen)."),
    "d_skipped": (
        "Sezioni del .map ignorate perché non riconducibili alla flash: {names}",
        "Sections of the .map ignored because they cannot be tied to flash: {names}",
        "Ignorierte Sektionen der .map, die sich nicht dem Flash zuordnen lassen: {names}"),
    "d_region_flash_hex": (
        "Regione '{name}' trattata come flash (contiene dati dell'HEX).",
        "Region '{name}' treated as flash (it contains HEX data).",
        "Region '{name}' wird als Flash behandelt (enthält HEX-Daten)."),
    "d_region_flash_sec": (
        "Regione '{name}' trattata come flash (contiene sezioni caricate).",
        "Region '{name}' treated as flash (it contains loaded sections).",
        "Region '{name}' wird als Flash behandelt (enthält geladene Sektionen)."),
    "d_region_unknown": (
        "Regione '{name}' ({org}, lunga {len}) non classificata: se è flash usa --flash-region {name}.",
        "Region '{name}' ({org}, length {len}) not classified: if it is flash use --flash-region {name}.",
        "Region '{name}' ({org}, Länge {len}) nicht klassifiziert: falls Flash, --flash-region {name} verwenden."),
    "d_overlap": (
        "{n} parole risultano assegnate a più di una sezione (tipico delle config word): conta la prima.",
        "{n} words are assigned to more than one section (typical of config words): the first one counts.",
        "{n} Worte sind mehr als einer Sektion zugeordnet (typisch für Config-Words): die erste zählt."),
    "d_ffpages": (
        "{pages} pagine sono presenti nell'HEX ma fuori dalle sezioni del .map contengono solo 0xFF ({bytes} byte, valore {val}): le considero vuote.",
        "{pages} pages are present in the HEX but hold only 0xFF outside the .map sections ({bytes} bytes, value {val}): treated as empty.",
        "{pages} Seiten sind im HEX vorhanden, enthalten außerhalb der .map-Sektionen aber nur 0xFF ({bytes} Byte, Wert {val}): sie gelten als leer."),
    "d_hexonly": (
        "{bytes} byte sono programmati nell'HEX ma non descritti dal .map (bootloader unito, fill della memoria, oppure HEX di un'altra build). Valori più frequenti: {vals}.",
        "{bytes} bytes are programmed in the HEX but not described by the .map (merged bootloader, memory fill, or a HEX from another build). Most frequent values: {vals}.",
        "{bytes} Byte sind im HEX programmiert, aber nicht in der .map beschrieben (eingebundener Bootloader, Speicher-Fill oder HEX eines anderen Builds). Häufigste Werte: {vals}."),
    "d_blank": (
        "{bytes} byte dentro sezioni del .map risultano 0xFFFFFF nell'HEX (dati a 0xFF o spazio riservato): vedi colonna 'vuoto nell'HEX' nel layout.",
        "{bytes} bytes inside .map sections read 0xFFFFFF in the HEX (0xFF data or reserved space): see the 'blank in HEX' column in the layout.",
        "{bytes} Byte innerhalb von .map-Sektionen sind im HEX 0xFFFFFF (0xFF-Daten oder reservierter Platz): siehe Spalte 'leer im HEX' im Layout."),
    "d_hex_outside": (
        "L'HEX contiene anche {n} parole oltre la flash principale ({a}-{b}): config/ID fuori mappa, non disegnate.",
        "The HEX also holds {n} words beyond the main flash ({a}-{b}): config/ID outside the map, not drawn.",
        "Das HEX enthält außerdem {n} Worte jenseits des Haupt-Flash ({a}-{b}): Config/ID außerhalb der Karte, nicht gezeichnet."),
    "d_no_hex": (
        "HEX non fornito: nessuna verifica su ciò che viene davvero programmato.",
        "No HEX given: no check against what is actually programmed.",
        "Kein HEX angegeben: keine Prüfung gegen das, was tatsächlich programmiert wird."),
    "d_outside_secs": (
        "Sezioni oltre la flash principale, non disegnate: {list}.",
        "Sections beyond the main flash, not drawn: {list}.",
        "Sektionen jenseits des Haupt-Flash, nicht gezeichnet: {list}."),
    "d_check_ok": (
        "Controllo: il linker dichiara {linker} byte usati nella regione program, io ne conto {mine}. Coincide.",
        "Check: the linker reports {linker} bytes used in the program region, this script counts {mine}. They match.",
        "Prüfung: der Linker meldet {linker} belegte Byte in der Region program, das Skript zählt {mine}. Stimmt überein."),
    "d_check_bad": (
        "Controllo: il linker dichiara {linker} byte usati nella regione program, io ne conto {mine} (differenza {diff}). Guarda le righe sopra per capire cosa manca.",
        "Check: the linker reports {linker} bytes used in the program region, this script counts {mine} (difference {diff}). See the lines above for what is missing.",
        "Prüfung: der Linker meldet {linker} belegte Byte in der Region program, das Skript zählt {mine} (Differenz {diff}). Die Zeilen oben zeigen, was fehlt."),
    "d_sym_dropped": (
        "{n} simboli dell'ELF hanno un indirizzo fuori dalla propria sezione: ignorati.",
        "{n} ELF symbols have an address outside their own section: ignored.",
        "{n} ELF-Symbole haben eine Adresse außerhalb ihrer Sektion: ignoriert."),
    "d_sym_none": (
        "L'ELF non contiene simboli utili (strippato?): uso i simboli globali del .map.",
        "The ELF holds no usable symbols (stripped?): using the global symbols from the .map.",
        "Das ELF enthält keine verwertbaren Symbole (gestrippt?): es werden die globalen Symbole der .map verwendet."),
    "d_sym_badsize": (
        "Le dimensioni dei simboli nell'ELF non tornano con gli indirizzi: uso le stime.",
        "Symbol sizes in the ELF do not agree with the addresses: using estimates.",
        "Die Symbolgrößen im ELF passen nicht zu den Adressen: es werden Schätzwerte verwendet."),
    "d_sym_octets": (
        "Le dimensioni dei simboli nell'ELF sono in ottetti (x{k}): convertite.",
        "Symbol sizes in the ELF are in octets (x{k}): converted.",
        "Die Symbolgrößen im ELF sind in Oktetten angegeben (x{k}): umgerechnet."),

    "bytes_word": ("byte", "bytes", "Byte"),

    # terminale
    "c_title": ("Mappa flash {dev}   ({tool})", "Flash map {dev}   ({tool})", "Flash-Belegung {dev}   ({tool})"),
    "c_total": ("Flash totale", "Total flash", "Flash gesamt"),
    "c_words": ("parole", "words", "Worte"),
    "c_used": ("Occupata", "Used", "Belegt"),
    "c_free": ("Libera", "Free", "Frei"),
    "c_free_d": ("buco più grande {max} byte, {pages} pagine da 0x{page} libere",
                 "largest hole {max} bytes, {pages} free pages of 0x{page}",
                 "größte Lücke {max} Byte, {pages} freie Seiten zu 0x{page}"),
    "c_reserved": ("Riservata vuota", "Reserved, empty", "Reserviert, leer"),
    "c_reserved_d": ("IVT / config non usate", "unused IVT / config", "ungenutzte IVT / Config"),
    "c_cat": ("Categoria", "Category", "Kategorie"),
    "c_pflash": ("% flash", "% flash", "% Flash"),
    "c_pused": ("% usato", "% used", "% belegt"),
    "c_mods": ("Moduli più pesanti", "Heaviest modules", "Schwerste Module"),
    "c_syms": ("Simboli più grossi", "Largest symbols", "Größte Symbole"),
    "c_addr": ("addr", "addr", "Adr."),
    "c_module": ("modulo", "module", "Modul"),
    "c_warn": ("Attenzione", "Warning", "Achtung"),
    "c_report": ("Report HTML: {path}", "HTML report: {path}", "HTML-Report: {path}"),
    "c_json": ("Dati JSON:   {path}", "JSON data:   {path}", "JSON-Daten:  {path}"),
    "c_notgiven": ("- (non fornito)", "- (not given)", "- (nicht angegeben)"),
    "c_unknown_dev": ("dispositivo sconosciuto", "unknown device", "unbekanntes Bauteil"),
    "c_unknown_tool": ("linker sconosciuto", "unknown linker", "unbekannter Linker"),

    # errori
    "e_hex_line": ("HEX: riga {ln} non valida in {path}", "HEX: invalid line {ln} in {path}", "HEX: ungültige Zeile {ln} in {path}"),
    "e_not_elf": ("ELF: {path} non è un file ELF", "ELF: {path} is not an ELF file", "ELF: {path} ist keine ELF-Datei"),
    "e_what": ("Non so cosa fare di '{path}': mi servono file .map, .elf, .hex o una cartella.",
               "Don't know what to do with '{path}': .map, .elf, .hex files or a folder are expected.",
               "Mit '{path}' kann ich nichts anfangen: erwartet werden .map-, .elf-, .hex-Dateien oder ein Ordner."),
    "e_missing": ("'{path}' non esiste.", "'{path}' does not exist.", "'{path}' existiert nicht."),
    "e_no_map": (
        "Mi serve il file .map del linker. In MPLAB X: proprietà del progetto -> linker (xc16-ld / xc-dsc-ld) -> 'Generate map file'; lo trovi poi in dist/<conf>/production/.",
        "The linker .map file is required. In MPLAB X: project properties -> linker (xc16-ld / xc-dsc-ld) -> 'Generate map file'; it then appears in dist/<conf>/production/.",
        "Die .map-Datei des Linkers wird benötigt. In MPLAB X: Projekteigenschaften -> Linker (xc16-ld / xc-dsc-ld) -> 'Generate map file'; sie liegt danach in dist/<conf>/production/."),
    "e_bad_map": (
        "Nel .map non trovo la parte 'Linker script and memory map': è un map di xc16-ld / xc-dsc-ld?",
        "The .map lacks the 'Linker script and memory map' part: is it a map from xc16-ld / xc-dsc-ld?",
        "In der .map fehlt der Teil 'Linker script and memory map': stammt sie von xc16-ld / xc-dsc-ld?"),
}


class Pct(object):
    """Percentuale da formattare secondo la lingua (virgola o punto decimale)."""
    def __init__(self, value, digits=1):
        self.value, self.digits = value, digits

    def fmt(self, lang):
        s = "%.*f%%" % (self.digits, self.value)
        return s if lang == "en" else s.replace(".", ",")


def fmt_int(n, lang=None):
    return "{:,}".format(int(n)).replace(",", "," if (lang or LANG) == "en" else ".")


def tr(key, **kw):
    """Testo nelle tre lingue: {'it': ..., 'en': ..., 'de': ...}. Gli interi vengono raggruppati per lingua."""
    out = {}
    for i, lang in enumerate(LANGS):
        args = {}
        for k, v in kw.items():
            if isinstance(v, Pct):
                args[k] = v.fmt(lang)
            elif isinstance(v, int) and not isinstance(v, bool):
                args[k] = fmt_int(v, lang)
            else:
                args[k] = v
        out[lang] = MSG[key][i].format(**args)
    return out


def loc(key, **kw):
    return tr(key, **kw)[LANG]


def die(key, **kw):
    raise SystemExit(loc(key, **kw))


def b3(pc_units):
    """Unità PC -> byte di flash (2 unità PC = 1 parola da 24 bit = 3 byte)."""
    return (pc_units * 3 + 1) // 2


def hx6(a):
    return "0x%06X" % a


def norm_path(p):
    return p.strip().replace("\\", "/")


# ----------------------------------------------------------------------------
# Intel HEX
# ----------------------------------------------------------------------------
def parse_hex(path):
    """Ritorna {indirizzo_PC_pari: valore_24_bit} per ogni parola presente nel file."""
    mem = {}
    base = 0
    with open(path, "r", encoding="latin-1") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line.startswith(":"):
                continue
            try:
                raw = bytes.fromhex(line[1:])
            except ValueError:
                die("e_hex_line", ln=str(ln), path=path)
            if len(raw) < 5:
                continue
            n, off, typ = raw[0], (raw[1] << 8) | raw[2], raw[3]
            data = raw[4:4 + n]
            if typ == 0:
                a = base + off
                for i, byte in enumerate(data):
                    mem[a + i] = byte
            elif typ == 2:
                base = int.from_bytes(data, "big") << 4
            elif typ == 4:
                base = int.from_bytes(data, "big") << 16
            elif typ == 1:
                break
    words = {}
    for w in {a >> 2 for a in mem}:
        a = w << 2
        words[w * 2] = (mem.get(a, 0xFF) | (mem.get(a + 1, 0xFF) << 8) | (mem.get(a + 2, 0xFF) << 16))
    return words


def ff_like(v):
    """Parola che contiene solo 0xFF come dato: 0xFFFFFF (cancellata) oppure 0x00FFFF
    (0xFFFF con byte alto a zero, come lo scrivono i fill a 16 bit e --fill-upper=0)."""
    return (v & 0xFFFF) == 0xFFFF and (v >> 16) in (0x00, 0xFF)


# ----------------------------------------------------------------------------
# ELF (parser minimale: intestazioni di sezione, segmenti, tabella simboli)
# ----------------------------------------------------------------------------
class Elf:
    SHT_PROGBITS, SHT_SYMTAB, SHT_NOBITS = 1, 2, 8
    SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4

    def __init__(self, path):
        with open(path, "rb") as f:
            d = f.read()
        if d[:4] != b"\x7fELF":
            die("e_not_elf", path=path)
        is64 = d[4] == 2
        e = "<" if d[5] == 1 else ">"
        if is64:
            (_t, self.machine, _v, self.entry, phoff, shoff, _fl, _eh, phentsize, phnum,
             shentsize, shnum, shstrndx) = struct.unpack_from(e + "HHIQQQIHHHHHH", d, 16)
        else:
            (_t, self.machine, _v, self.entry, phoff, shoff, _fl, _eh, phentsize, phnum,
             shentsize, shnum, shstrndx) = struct.unpack_from(e + "HHIIIIIHHHHHH", d, 16)

        self.sections = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if is64:
                name, typ, flags, addr, off, size, link, _info, _al, entsize = struct.unpack_from(e + "IIQQQQIIQQ", d, o)
            else:
                name, typ, flags, addr, off, size, link, _info, _al, entsize = struct.unpack_from(e + "IIIIIIIIII", d, o)
            self.sections.append(dict(idx=i, name_off=name, type=typ, flags=flags, addr=addr,
                                      offset=off, size=size, link=link, entsize=entsize, name=""))

        def cstr(tab, off):
            if off >= len(tab):
                return ""
            end = tab.find(b"\0", off)
            return tab[off:end if end >= 0 else len(tab)].decode("latin-1")

        if 0 < shstrndx < len(self.sections):
            s = self.sections[shstrndx]
            tab = d[s["offset"]:s["offset"] + s["size"]]
            for s in self.sections:
                s["name"] = cstr(tab, s["name_off"])

        self.segments = []
        for i in range(phnum):
            o = phoff + i * phentsize
            if is64:
                typ, _fl, off, vaddr, paddr, filesz, memsz, _al = struct.unpack_from(e + "IIQQQQQQ", d, o)
            else:
                typ, off, vaddr, paddr, filesz, memsz, _fl, _al = struct.unpack_from(e + "IIIIIIII", d, o)
            self.segments.append(dict(type=typ, offset=off, vaddr=vaddr, paddr=paddr, filesz=filesz, memsz=memsz))

        self.symbols = []
        for s in self.sections:
            if s["type"] != self.SHT_SYMTAB:
                continue
            strs = self.sections[s["link"]] if s["link"] < len(self.sections) else None
            strtab = d[strs["offset"]:strs["offset"] + strs["size"]] if strs else b""
            ent = s["entsize"] or (24 if is64 else 16)
            for i in range(s["size"] // ent):
                o = s["offset"] + i * ent
                if is64:
                    name, info, _other, shndx, value, size = struct.unpack_from(e + "IBBHQQ", d, o)
                else:
                    name, value, size, info, _other, shndx = struct.unpack_from(e + "IIIBBH", d, o)
                self.symbols.append(dict(name=cstr(strtab, name), value=value, size=size,
                                         type=info & 0xF, bind=info >> 4, shndx=shndx))


# ----------------------------------------------------------------------------
# MAP del linker (xc16-ld / xc-dsc-ld)
# ----------------------------------------------------------------------------
HEXN = r"0x[0-9a-fA-F]+"
RE_REPORT = re.compile(r'^"([^"]+)" Memory\s+\[Origin = (%s), Length = (%s)\]' % (HEXN, HEXN))
RE_REPORT_ROW = re.compile(r"^(\S+)\s+(%s)\s+(%s|\d+)\s+(%s)\s+\((\d+)\)" % (HEXN, HEXN, HEXN))
RE_TOTAL = re.compile(r'Total "([^"]+)" memory used \(bytes\):\s+(%s)\s+\((\d+)\)' % HEXN)
RE_MEMCFG = re.compile(r"^(\S+)\s+(%s)\s+(%s)\s*(.*)$" % (HEXN, HEXN))
RE_OUT_FULL = re.compile(r"^(\S+)\s+(%s)\s+(%s)(?:\s+(.*))?$" % (HEXN, HEXN))
RE_CONT = re.compile(r"^\s+(%s)\s+(%s)(?:\s+(\S.*))?$" % (HEXN, HEXN))
RE_IN_FULL = re.compile(r"^ (\S+)\s+(%s)\s+(%s)\s+(\S.*)$" % (HEXN, HEXN))
RE_FILL = re.compile(r"^ \*fill\*\s+(%s)\s+(%s)" % (HEXN, HEXN))
RE_SYM = re.compile(r"^\s+(%s)\s+(\S+)$" % HEXN)
RE_EXT_SYM = re.compile(r"^\s+(%s)\s+(\S+)\s*$" % HEXN)
RE_LOADADDR = re.compile(r"load address (%s)" % HEXN)
RE_ARCH_MEMBER = re.compile(r"^(\S.*\.a\([^()]+\))\s*(.*)$")
RE_ARCH_WHY = re.compile(r"^(.*?)\s*\((\S+)\)\s*$")
DIRECTIVES = ("SHORT", "LONG", "BYTE", "QUAD", "SQUAD", "FILL")


def parse_map(path):
    mp = dict(tool="", command=[], device="", models={}, reports={}, totals={},
              ext_syms={}, regions=[], osecs=[], why={}, path=path)
    with open(path, "r", encoding="latin-1") as f:
        lines = [l.rstrip("\r\n") for l in f]

    mode = None
    report = None
    cur_member = None
    cur_osec = None
    cur_piece = None
    pending_out = None
    pending_in = None

    for i, line in enumerate(lines):
        s = line.strip()
        if i == 0:
            mp["tool"] = s

        # ---- parte finale: "Linker script and memory map" -------------------
        if mode == "memmap":
            if not s:
                pending_out = pending_in = None
                continue
            if line[0] != " " and line[0] != "\t":
                cur_piece = None
                pending_in = None
                if s.startswith(("LOAD ", "OUTPUT(", "START GROUP", "END GROUP")):
                    cur_osec = None
                    pending_out = None
                    continue
                m = RE_OUT_FULL.match(line)
                if m:
                    cur_osec = _new_osec(mp, m.group(1), m.group(2), m.group(3), m.group(4))
                    pending_out = None
                elif len(s.split()) == 1:
                    pending_out = s
                    cur_osec = None
                else:
                    cur_osec = None
                    pending_out = None
                continue
            if pending_out is not None:
                m = RE_CONT.match(line)
                if m and not (m.group(3) or "").startswith(DIRECTIVES):
                    cur_osec = _new_osec(mp, pending_out, m.group(1), m.group(2), m.group(3))
                    pending_out = None
                    continue
                pending_out = None
            if line.startswith(" ") and not line.startswith("  "):
                m = RE_FILL.match(line)
                if m:
                    if cur_osec is not None:
                        cur_osec["pieces"].append(dict(name="*fill*", addr=int(m.group(1), 16),
                                                       size=int(m.group(2), 16), module="", fill=True, syms=[]))
                    cur_piece = None
                    pending_in = None
                    continue
                m = RE_IN_FULL.match(line)
                if m and not m.group(1).startswith("*"):
                    cur_piece = _new_piece(cur_osec, m.group(1), m.group(2), m.group(3), m.group(4))
                    pending_in = None
                    continue
                toks = s.split()
                if len(toks) == 1 and not toks[0].startswith("*") and "(" not in toks[0]:
                    pending_in = toks[0]
                else:
                    pending_in = None
                cur_piece = None
                continue
            if pending_in is not None:
                m = RE_CONT.match(line)
                if m and m.group(3) and not m.group(3).startswith(DIRECTIVES):
                    cur_piece = _new_piece(cur_osec, pending_in, m.group(1), m.group(2), m.group(3))
                    pending_in = None
                    continue
                pending_in = None
            m = RE_SYM.match(line)
            if m and cur_piece is not None and not m.group(2).lower().startswith("0x"):
                name = m.group(2)
                if ".o:" in name or ".obj:" in name:        # forma "percorso.o:simbolo"
                    name = name.rsplit(":", 1)[1]
                if name and not LOCAL_LABEL_RE.search(name):
                    cur_piece["syms"].append((int(m.group(1), 16), name))
            continue

        # ---- intestazioni che cambiano modalità ------------------------------
        if s == "Command:":
            mode = "cmd"
            continue
        if s.startswith("Archive member included"):
            mode = "arch"
            cur_member = None
            continue
        if s.startswith("Linker script and memory map"):
            mode = "memmap"
            continue
        if s == "Memory Configuration":
            mode = "memcfg"
            continue
        if s.startswith("External Symbols in Program Memory (by address)"):
            mode = "psyms"
            continue
        if s.startswith(("External Symbols", "Dynamic Memory Usage", "Selected CodeGuard",
                         "CodeGuard ", "Memory Usage Report", "Allocating common symbols",
                         "Discarded input sections", "Cross Reference Table")):
            mode = None
            continue
        m = RE_REPORT.match(s)
        if m:
            report = dict(origin=int(m.group(2), 16), length=int(m.group(3), 16), kind=None, rows=[])
            mp["reports"][m.group(1)] = report
            mode = "report"
            continue
        m = re.match(r"^Default (Code|Data|Scalar) Model:\s*(\S+)", s)
        if m:
            mp["models"][m.group(1).lower()] = m.group(2)
            mode = None
            continue

        # ---- contenuto per modalità ------------------------------------------
        if mode == "cmd":
            if not s:
                mode = None
                continue
            opt = s[:-1].strip() if s.endswith("\\") else s
            mp["command"].append(opt)
            m = re.match(r"^-p(\w+)$", opt)
            if m:
                mp["device"] = m.group(1)
        elif mode == "arch":
            if not s:
                continue
            m = RE_ARCH_MEMBER.match(line) if line[0] not in " \t" else None
            if m:
                cur_member = norm_path(m.group(1)).lower()
                rest = m.group(2).strip()
            else:
                rest = s
            if rest and cur_member:
                w = RE_ARCH_WHY.match(rest)
                if w:
                    mp["why"].setdefault(cur_member, (norm_path(w.group(1)), w.group(2)))
        elif mode == "report":
            if "length (PC units)" in s:
                report["kind"] = "program"
            elif "alignment gaps" in s:
                report["kind"] = "data"
            else:
                t = RE_TOTAL.search(s)
                if t:
                    mp["totals"][t.group(1)] = int(t.group(3))
                    mode = None
                    continue
                m = RE_REPORT_ROW.match(s)
                if m:
                    report["rows"].append((m.group(1), int(m.group(2), 16), int(m.group(3), 0),
                                           int(m.group(5))))
        elif mode == "psyms":
            m = RE_EXT_SYM.match(line)
            if m:
                mp["ext_syms"][m.group(2)] = int(m.group(1), 16)
        elif mode == "memcfg":
            m = RE_MEMCFG.match(s)
            if m and m.group(1) != "*default*":
                mp["regions"].append(dict(name=m.group(1), org=int(m.group(2), 16),
                                          len=int(m.group(3), 16), attrs=m.group(4).strip()))
    return mp


def _new_osec(mp, name, addr, size, rest):
    o = dict(name=name, addr=int(addr, 16), size=int(size, 16), lma=None, pieces=[])
    m = RE_LOADADDR.search(rest or "")
    if m:
        o["lma"] = int(m.group(1), 16)
    mp["osecs"].append(o)
    return o


def _new_piece(osec, name, addr, size, module):
    if osec is None:
        return None
    p = dict(name=name, addr=int(addr, 16), size=int(size, 16), module=norm_path(module), fill=False, syms=[])
    osec["pieces"].append(p)
    return p


# ----------------------------------------------------------------------------
# Moduli (file oggetto / membri di libreria)
# ----------------------------------------------------------------------------
class Modules:
    LINKER = "(linker)"

    def __init__(self, why):
        self.by_key = {}
        self.list = []
        self.why = why

    def get(self, raw):
        raw = raw or self.LINKER
        key = raw.lower()
        if key in self.by_key:
            return self.by_key[key]
        m = re.match(r"^(.*\.a)\(([^()]+)\)$", raw)
        if m:
            lib = os.path.basename(m.group(1))
            name = "%s(%s)" % (lib, m.group(2))
            kind = "lib"
        elif "/" not in raw and not re.search(r"\.(o|obj)$", raw, re.I):
            lib, name, kind = "", raw, "linker"       # jump_table, default_isr, data_init, ...
        elif raw.startswith("/CW/"):
            lib, name, kind = "", raw, "linker"
        else:
            lib, name, kind = "", os.path.basename(raw), "app"
        why = self.why.get(key)
        mod = dict(idx=len(self.list), key=key, full=raw, name=name, lib=lib, kind=kind,
                   wsym=why[1] if why else "", wref=_short_ref(why[0]) if why else "",
                   bytes=0, bycat=collections.Counter())
        self.by_key[key] = mod
        self.list.append(mod)
        return mod

    def disambiguate(self):
        seen = collections.defaultdict(list)
        for m in self.list:
            seen[m["name"]].append(m)
        for name, mods in seen.items():
            if len(mods) > 1:
                for m in mods:
                    parts = m["full"].split("/")
                    if len(parts) >= 2 and m["kind"] == "app":
                        m["name"] = "/".join(parts[-2:])


def _short_ref(ref):
    if not ref:
        return ""                                   # radice del link
    m = re.match(r"^(.*\.a)\(([^()]+)\)$", ref)
    if m:
        return "%s(%s)" % (os.path.basename(m.group(1)), m.group(2))
    return os.path.basename(ref)


# ----------------------------------------------------------------------------
# Costruzione del modello
# ----------------------------------------------------------------------------
def classify_regions(mp, flash_force, ram_force):
    regs = []
    for r in mp["regions"]:
        name, low = r["name"], r["name"].lower()
        pos, neg, negate = set(), set(), False
        for ch in r["attrs"]:
            if ch == "!":
                negate = True
            elif ch.isspace():
                negate = False
            else:
                (neg if negate else pos).add(ch)
        rep = mp["reports"].get(name)
        if low in ram_force:
            kind = "ram"
        elif low in flash_force:
            kind = "program"
        elif rep and rep["kind"] == "program":
            kind = "program"
        elif rep and rep["kind"] == "data":
            kind = "ram"
        elif "x" in pos:
            kind = "program"
        elif "x" in neg:
            kind = "ram"
        elif low == "reset":
            kind = "reset"
        elif low in ("ivt", "aivt"):
            kind = "ivt"
        elif re.match(r"^F[A-Z0-9_]+$", name) and r["len"] <= 8:
            kind = "config"
        elif low in RAM_REGION_NAMES:
            kind = "ram"
        else:
            kind = "unknown"
        regs.append(dict(name=name, org=r["org"], len=r["len"], end=r["org"] + r["len"], kind=kind, attrs=r["attrs"]))
    return regs


def categorize(sec_name, piece_name, mod_kind, region_kind, is_exec, fill):
    n = piece_name or sec_name
    if fill:
        return CAT["pad"]
    if region_kind == "config" or n.startswith(("__F", ".config")) or sec_name.startswith(("__F", ".config")):
        return CAT["config"]
    if sec_name.startswith(".reset") or region_kind == "reset":
        return CAT["startup"]
    if n.startswith((".ivt", ".aivt")) or sec_name.startswith((".ivt", ".aivt")) or region_kind == "ivt":
        return CAT["ivt"]
    if n.startswith(".dinit") or sec_name == ".dinit":
        return CAT["dinit"]
    if n.startswith((".init", ".user_init")):
        return CAT["startup"]
    if n.startswith(".isr"):
        return CAT["isr"]
    if n.startswith((".const", ".rodata", ".boot_const", ".secure_const")) or sec_name.startswith(".const") \
            or "psv" in n.lower() or is_exec is False:
        return CAT["const"]
    if mod_kind in ("lib", "linker"):
        return CAT["code_lib"]
    return CAT["code_app"]


def build_model(mp, elf, hexw, args):
    diag = []           # (livello, testo nelle tre lingue)   livello: info | warn

    def note(lvl, key, **kw):
        diag.append((lvl, tr(key, **kw)))

    # ---- regioni ------------------------------------------------------------
    flash_force = {x.lower() for x in args.flash_region}
    ram_force = {x.lower() for x in args.ram_region}
    regions = classify_regions(mp, flash_force, ram_force)
    if not regions:
        note("warn", "d_no_memcfg")

    # ---- sezioni di output in flash ------------------------------------------
    prog_rows = [(n, a, l) for rep in mp["reports"].values() if rep["kind"] == "program" for (n, a, l, _b) in rep["rows"]]
    data_rows = {(n, a) for rep in mp["reports"].values() if rep["kind"] == "data" for (n, a, _l, _b) in rep["rows"]}
    prog_set = {(n, a) for (n, a, _l) in prog_rows}

    # controllo del rapporto byte / unità PC (1.5 su dsPIC33C/E/F e PIC24; 1 su dsPIC33A)
    for rep in mp["reports"].values():
        if rep["kind"] == "program":
            big = [(l, b) for (_n, _a, l, b) in rep["rows"] if l >= 16]
            if big and all(abs(b / l - 1.0) < 0.05 for l, b in big):
                note("warn", "d_pc_bytes")
            break

    sections = []       # dict(name, vma, lma, size, exec, osec, elf_idx)
    elf_sec_to_sec = {}
    opb = 2
    if elf:
        osec_by_key = {}
        for o in mp["osecs"]:
            if o["size"] > 0:
                osec_by_key.setdefault((o["name"], o["addr"]), o)
        loads = [g for g in elf.segments if g["type"] == 1 and g["filesz"] > 0]
        # calibrazione: quanti ottetti nel file per unità PC (2 su pic30)
        votes = collections.Counter()
        for s in elf.sections:
            o = osec_by_key.get((s["name"], s["addr"]))
            if o and s["type"] == Elf.SHT_PROGBITS and s["flags"] & Elf.SHF_ALLOC and o["size"]:
                votes[round(s["size"] / o["size"], 2)] += 1
        if votes:
            ratio = votes.most_common(1)[0][0]
            if ratio in (1.0, 2.0):
                opb = int(ratio)
            else:
                note("warn", "d_elf_ratio", ratio="%.2f" % ratio)
        else:
            note("warn", "d_elf_nomatch")
        for s in elf.sections:
            if s["type"] != Elf.SHT_PROGBITS or not (s["flags"] & Elf.SHF_ALLOC) or (s["flags"] & Elf.SHF_WRITE) or s["size"] == 0:
                continue
            vma = s["addr"]
            lma = vma
            for g in loads:
                if g["offset"] <= s["offset"] < g["offset"] + g["filesz"]:
                    d = (s["offset"] - g["offset"]) // opb
                    if g["vaddr"] + d == vma:
                        lma = g["paddr"] + d
                    break
            o = osec_by_key.get((s["name"], vma))
            if o and o["lma"] is not None and o["lma"] != lma:
                note("info", "d_lma_diff", name=s["name"], elf=hx6(lma), map=hx6(o["lma"]))
            sec = dict(name=s["name"], vma=vma, lma=lma, size=s["size"] // opb,
                       exec=bool(s["flags"] & Elf.SHF_EXEC), osec=o, elf_idx=s["idx"])
            elf_sec_to_sec[s["idx"]] = sec
            sections.append(sec)
        elf_keys = {(x["name"], x["lma"]) for x in sections}
        missing = [(n, a) for (n, a, _l) in prog_rows if (n, a) not in elf_keys]
        if missing:
            note("warn", "d_elf_missing", n=len(missing), name=missing[0][0], addr="0x%X" % missing[0][1])
    else:
        note("info", "d_no_elf")
        small_regions = [r for r in regions if r["kind"] in ("reset", "ivt", "config")]
        skipped = []
        for o in mp["osecs"]:
            if o["size"] == 0:
                continue
            name, addr, size = o["name"], o["addr"], o["size"]
            lma = None
            if o["lma"] is not None:
                lma = o["lma"]
            elif (name, addr) in prog_set:
                lma = addr
            else:
                for (n, a, l) in prog_rows:      # .const mostrata all'indirizzo PSV (bit 15 a 1)
                    if n == name and l == size and addr >= 0x8000 and (a & 0x7FFF) == (addr & 0x7FFF):
                        lma = a
                        break
            if lma is None:
                if (name, addr) in data_rows or DEBUG_SECTION_RE.match(name):
                    continue
                if any(r["org"] <= addr and addr + size <= r["end"] for r in small_regions):
                    lma = addr
                else:
                    skipped.append(name)
                    continue
            sections.append(dict(name=name, vma=addr, lma=lma, size=size, exec=None, osec=o, elf_idx=None))
        if skipped:
            uniq = sorted(set(skipped))
            note("info", "d_skipped", names=", ".join(uniq[:8]) + (" ..." if len(uniq) > 8 else ""))

    # ---- regioni sconosciute: flash se contengono sezioni flash o parole dell'HEX ---
    for r in regions:
        if r["kind"] != "unknown":
            continue
        has_sec = any(r["org"] <= s["lma"] < r["end"] for s in sections)
        has_hex = False
        if hexw and r["len"] <= 0x100000:
            has_hex = any(r["org"] <= a < r["end"] and v != 0xFFFFFF for a, v in hexw.items())
        if has_hex:
            r["kind"] = "program"
            note("info", "d_region_flash_hex", name=r["name"])
        elif has_sec:
            r["kind"] = "program"
            note("info", "d_region_flash_sec", name=r["name"])
        else:
            note("warn", "d_region_unknown", name=r["name"], org="0x%X" % r["org"], len="0x%X" % r["len"])

    flash_regions = [r for r in regions if r["kind"] in ("program", "reset", "ivt", "config")]
    main_regions = [r for r in flash_regions if r["org"] < 0x800000]
    if args.flash_end:
        flash_end = args.flash_end
    elif main_regions:
        flash_end = max(r["end"] for r in main_regions)
        flash_end = (flash_end + PAGE - 1) // PAGE * PAGE
    else:
        flash_end = max([s["lma"] + s["size"] for s in sections if s["lma"] < 0x800000] or [0x2C000])
        flash_end = (flash_end + PAGE - 1) // PAGE * PAGE
        regions.append(dict(name="flash", org=0, len=flash_end, end=flash_end, kind="program", attrs=""))
    nwords = flash_end // 2

    outside = [s for s in sections if s["lma"] >= flash_end]
    sections = sorted([s for s in sections if s["lma"] < flash_end], key=lambda s: (s["lma"], -s["size"]))
    for i, s in enumerate(sections):
        s["idx"] = i

    # ---- mappa parola -> regione ---------------------------------------------
    KCODE = {"program": 1, "reset": 2, "ivt": 3, "config": 4}
    rk = bytearray(nwords)
    rix = array.array("h", [-1]) * nwords
    order = sorted(range(len(regions)), key=lambda i: -regions[i]["len"])      # le piccole sovrascrivono le grandi
    for i in order:
        r = regions[i]
        if r["kind"] not in KCODE:
            continue
        for w in range(max(0, r["org"] // 2), min(nwords, (r["end"] + 1) // 2)):
            rk[w] = KCODE[r["kind"]]
            rix[w] = i
    KNAME = {v: k for k, v in KCODE.items()}

    def region_kind_at(addr):
        w = addr // 2
        return KNAME.get(rk[w]) if 0 <= w < nwords else None

    # ---- foglie: (sezione, parte, modulo) e proprietà delle parole -------------
    mods = Modules(mp["why"])
    names = []
    name_idx = {}

    def nid(s):
        if s not in name_idx:
            name_idx[s] = len(names)
            names.append(s)
        return name_idx[s]

    # etichette locali tipo ".handle": danno un nome ai blocchi che il .map non elenca
    sec_labels = {}
    if elf:
        for y in elf.symbols:
            if y["type"] == 0 and y["bind"] == 0 and y["name"].startswith(".") and not LOCAL_LABEL_RE.search(y["name"]):
                sec_labels.setdefault((y["shndx"], y["value"]), y["name"])

    leaves = []         # dict(sec, mod, name, cat, addr, size)
    own = array.array("l", [G_FREE]) * nwords
    overlap_words = 0

    def add_leaf(sec, a0, a1, pname, module, fill=False):
        nonlocal overlap_words
        a0, a1 = max(a0, sec["lma"]), min(a1, sec["lma"] + sec["size"], flash_end)
        if a1 <= a0:
            return
        if not pname and sec["elf_idx"] is not None:
            pname = sec_labels.get((sec["elf_idx"], a0 - (sec["lma"] - sec["vma"])), "")
        mod = mods.get(module)
        cat = categorize(sec["name"], pname, mod["kind"], region_kind_at(a0), sec["exec"], fill)
        li = len(leaves)
        leaves.append(dict(sec=sec["idx"], mod=mod["idx"], name=nid(pname or sec["name"]), cat=cat, addr=a0, size=a1 - a0))
        for w in range(a0 // 2, (a1 + 1) // 2):
            if own[w] < 0:
                own[w] = li
            else:
                overlap_words += 1

    for sec in sections:
        o = sec["osec"]
        delta = sec["lma"] - sec["vma"]
        sec["delta"] = delta
        cur = sec["lma"]
        end = sec["lma"] + sec["size"]
        pieces = sorted((p for p in (o["pieces"] if o else []) if p["size"] > 0), key=lambda p: p["addr"])
        for p in pieces:
            a0, a1 = p["addr"] + delta, p["addr"] + delta + p["size"]
            if a1 <= sec["lma"] or a0 >= end:
                continue
            if a0 > cur:
                add_leaf(sec, cur, a0, "", "")
            add_leaf(sec, max(a0, cur), a1, p["name"], p["module"], p["fill"])
            cur = max(cur, a1)
        if cur < end:
            add_leaf(sec, cur, end, "", "")
    mods.disambiguate()
    if overlap_words:
        note("info", "d_overlap", n=overlap_words)

    # ---- HEX -------------------------------------------------------------------
    hp = bytearray(nwords)      # 1 = parola con contenuto (diversa da 0xFFFFFF)
    hex_outside = []
    if hexw is not None:
        for a, v in hexw.items():
            if v == 0xFFFFFF:
                continue
            w = a // 2
            if w < nwords:
                hp[w] = 1
            else:
                hex_outside.append(a)
        # Pagine "tutte a 0xFF": se, fuori dalle sezioni del .map, una pagina contiene solo
        # parole 0x00FFFF (0xFFFF di dato, byte alto a zero) è un riempimento, non contenuto:
        # va mostrata come vuota e non come "solo nell'HEX".
        ff_pages = ff_words = 0
        ff_vals = collections.Counter()
        for p0 in range(0, flash_end, PAGE):
            ws = [w for w in range(p0 // 2, min(nwords, (p0 + PAGE) // 2)) if own[w] == G_FREE and hp[w]]
            if ws and all(ff_like(hexw.get(w * 2, 0xFFFFFF)) for w in ws):
                for w in ws:
                    hp[w] = 0
                    ff_vals[hexw.get(w * 2, 0xFFFFFF)] += 1
                ff_pages += 1
                ff_words += len(ws)
        if ff_pages:
            note("info", "d_ffpages", pages=ff_pages, bytes=ff_words * 3, val=hx6(ff_vals.most_common(1)[0][0]))
        for w in range(nwords):
            if own[w] == G_FREE and hp[w]:
                own[w] = {3: G_HEX_IVT, 4: G_HEX_CFG, 2: G_HEX_RESET}.get(rk[w], G_HEXONLY)
    for w in range(nwords):
        if own[w] == G_FREE:
            k = rk[w]
            if k == 0:
                own[w] = G_UNMAPPED
            elif k != 1:
                own[w] = G_RESERVED

    # ---- run (intervalli omogenei) ------------------------------------------------
    runs = []           # [addr, len, cat, leaf]
    w = 0
    while w < nwords:
        v = own[w]
        e = w + 1
        while e < nwords and own[e] == v:
            e += 1
        cat = leaves[v]["cat"] if v >= 0 else GAP_CAT[v]
        runs.append([w * 2, (e - w) * 2, cat, v if v >= 0 else -1])
        w = e

    # ---- statistiche ------------------------------------------------------------
    cat_words = collections.Counter()
    for s in sections:
        s["used"] = 0
        s["blank"] = 0
    for a, l, c, lf in runs:
        cat_words[c] += l // 2
        if lf >= 0:
            m = mods.list[leaves[lf]["mod"]]
            m["bytes"] += b3(l)
            m["bycat"][c] += b3(l)
            s = sections[leaves[lf]["sec"]]
            s["used"] += l
            if hexw is not None:
                s["blank"] += sum(1 for ww in range(a // 2, (a + l) // 2) if not hp[ww]) * 2

    for r in regions:
        r["used"] = r["free"] = r["maxfree"] = 0
    for a, l, c, lf in runs:
        # un run può attraversare più regioni solo se è un buco: spezzalo
        ww, wend = a // 2, (a + l) // 2
        while ww < wend:
            ri = rix[ww]
            e = ww + 1
            while e < wend and rix[e] == ri:
                e += 1
            if ri >= 0:
                r = regions[ri]
                if c in USED_CATS:
                    r["used"] += (e - ww) * 2
                else:
                    r["free"] += (e - ww) * 2
                    r["maxfree"] = max(r["maxfree"], (e - ww) * 2)
            ww = e

    free_pages = 0
    for p0 in range(0, flash_end, PAGE):
        if all(own[ww] == G_FREE for ww in range(p0 // 2, min(nwords, (p0 + PAGE) // 2))):
            free_pages += 1

    holes = [(a, l) for a, l, c, lf in runs if c == CAT["free"]]

    # ---- simboli ------------------------------------------------------------------
    symbols, sym_notes = build_symbols(mp, elf, sections, elf_sec_to_sec, leaves, own)
    diag.extend(sym_notes)

    # ---- layout in ordine di indirizzo ----------------------------------------------
    layout = build_layout(sections, runs, regions, rix, leaves)

    # ---- verifica HEX ------------------------------------------------------------------
    if hexw is not None:
        hexonly_runs = [(a, l) for a, l, c, lf in runs if c == CAT["hexonly"]]
        vals = collections.Counter(hexw[a2] for a, l in hexonly_runs for a2 in range(a, a + l, 2) if a2 in hexw)
        blank_in_sec = sum(s["blank"] for s in sections)
        hexonly_bytes = sum(l for a, l in hexonly_runs) // 2 * 3
        if hexonly_bytes:
            top = ", ".join("%s x%d" % (hx6(v), n) for v, n in vals.most_common(3))
            note("warn", "d_hexonly", bytes=hexonly_bytes, vals=top)
        if blank_in_sec:
            note("info", "d_blank", bytes=b3(blank_in_sec))
        if hex_outside:
            note("info", "d_hex_outside", n=len(hex_outside), a=hx6(min(hex_outside)), b=hx6(max(hex_outside)))
    else:
        note("info", "d_no_hex")
    if outside:
        note("info", "d_outside_secs", list=", ".join("%s@0x%X" % (s["name"], s["lma"]) for s in outside[:6]))

    # ---- confronto con il totale del linker -------------------------------------------
    prog_used = sum(r["used"] for r in regions if r["kind"] == "program")
    prog_size = sum(r["len"] for r in regions if r["kind"] == "program" and r["org"] < flash_end)
    linker_total = mp["totals"].get("program")
    if linker_total is not None:
        mine = sum(b3(l) for a, l, c, lf in runs if lf >= 0 and rk[a // 2] == 1)
        if abs(mine - linker_total) <= max(8, linker_total * 0.002):
            note("info", "d_check_ok", linker=linker_total, mine=mine)
        else:
            note("warn", "d_check_bad", linker=linker_total, mine=mine, diff=mine - linker_total)

    totals = dict(
        flash=nwords * 3, flash_end=flash_end,
        used=sum(cat_words[c] for c in USED_CATS) * 3,
        free=cat_words[CAT["free"]] * 3,
        reserved=cat_words[CAT["reserved"]] * 3,
        unmapped=cat_words[CAT["unmapped"]] * 3,
        prog_size=b3(prog_size), prog_used=b3(prog_used),
        maxfree=b3(max([l for a, l in holes] or [0])),
        free_pages=free_pages, page=PAGE,
        linker_total=linker_total,
    )

    model = dict(
        mp=mp, regions=regions, sections=sections, leaves=leaves, runs=runs, names=names,
        mods=mods.list, symbols=symbols, layout=layout, totals=totals, cat_words=cat_words,
        hp=hp, diag=diag, has_elf=bool(elf), has_hex=hexw is not None,
    )
    return model


def build_symbols(mp, elf, sections, elf_sec_to_sec, leaves, own):
    notes = []
    cands = []          # (addr, name, st_size, type, bind, sec)
    if elf:
        dropped = 0
        for s in elf.symbols:
            sec = elf_sec_to_sec.get(s["shndx"])
            if sec is None or "idx" not in sec or not s["name"]:
                continue
            t, bind, name = s["type"], s["bind"], s["name"]
            if t not in (0, 1, 2):            # NOTYPE, OBJECT, FUNC
                continue
            if LOCAL_LABEL_RE.search(name):
                continue
            if t == 0 and bind == 0 and not name.startswith("_"):
                continue                      # etichette locali dell'assembler dentro le funzioni
            v = s["value"]
            if sec["vma"] <= v < sec["vma"] + sec["size"]:
                addr = v + sec["delta"]
            elif sec["lma"] <= v < sec["lma"] + sec["size"]:
                addr = v
            else:
                dropped += 1
                continue
            cands.append((addr, name, s["size"], {1: "O", 2: "F"}.get(t, "-"), bind, sec))
        if dropped:
            notes.append(("info", tr("d_sym_dropped", n=dropped)))
        if not cands:
            notes.append(("warn", tr("d_sym_none")))
    if not cands:
        for sec in sections:
            o = sec["osec"]
            if not o:
                continue
            for p in o["pieces"]:
                for a, name in p["syms"]:
                    cands.append((a + sec["delta"], name, 0, "-", 1, sec))

    # confini: indirizzi distinti dei simboli + fine di ogni foglia
    by_addr = collections.defaultdict(list)
    for c in cands:
        by_addr[c[0]].append(c)
    addrs = sorted(by_addr)

    def leaf_end(addr):
        w = addr // 2
        if 0 <= w < len(own) and own[w] >= 0:
            lf = leaves[own[w]]
            return lf["addr"] + lf["size"], own[w]
        return None, -1

    gaps = {}
    for i, a in enumerate(addrs):
        end, lf = leaf_end(a)
        if end is None:
            continue
        nxt = addrs[i + 1] if i + 1 < len(addrs) else end
        gaps[a] = (min(nxt, end) - a if nxt > a else end - a, lf)

    # calibrazione dell'unità di st_size (unità PC su XC16; per sicurezza si verifica)
    k = None
    sized = [(c[2], gaps[c[0]][0]) for c in cands if c[2] > 0 and c[0] in gaps and gaps[c[0]][0] > 0]
    if sized:
        for cand_k in (1, 2):
            ok = sum(1 for sz, g in sized if sz / cand_k <= g) / len(sized)
            if ok >= 0.9:
                k = cand_k
                break
        if k is None:
            notes.append(("warn", tr("d_sym_badsize")))
        elif k != 1:
            notes.append(("info", tr("d_sym_octets", k=str(k))))

    out = []
    for a in addrs:
        if a not in gaps:
            continue
        gap, lf = gaps[a]
        group = sorted(by_addr[a], key=lambda c: (c[2] == 0, {1: 0, 2: 1, 0: 2}.get(c[4], 3), len(c[1])))
        addr, name, st_size, typ, bind, sec = group[0]
        est = True
        size = gap
        if k and st_size > 0:
            decl = st_size // k
            decl += decl & 1
            if decl <= gap:
                size, est = decl, False
        if size <= 0:
            continue
        leaf = leaves[lf]
        aliases = [c[1] for c in group[1:] if c[1] != name]
        out.append(dict(addr=addr, size=size, name=name, type=typ, local=(bind == 0), est=est,
                        cat=leaf["cat"], mod=leaf["mod"], sec=leaf["sec"], aliases=aliases))
    return out, notes


def build_layout(sections, runs, regions, rix, leaves):
    """Righe in ordine di indirizzo: sezioni (con le famiglie di micro-sezioni raggruppate) e buchi."""
    def family(name):
        for pre in (".ivt.", ".aivt.", ".config_", "__F"):
            if name.startswith(pre):
                return pre
        return None

    blocks = []
    for s in sections:
        fam = family(s["name"])
        if fam and blocks and blocks[-1].get("fam") == fam and s["lma"] - blocks[-1]["end"] <= 0x100:
            b = blocks[-1]
            b["end"] = max(b["end"], s["lma"] + s["size"])
            b["used"] += s["used"]
            b["blank"] += s["blank"]
            b["n"] += 1
            b["secs"].append(s["idx"])
            continue
        blocks.append(dict(fam=fam, name=s["name"], start=s["lma"], end=s["lma"] + s["size"], used=s["used"],
                           blank=s["blank"], n=1, secs=[s["idx"]], cat=None))
    sec_cats = collections.defaultdict(collections.Counter)
    for lf in leaves:
        sec_cats[lf["sec"]][lf["cat"]] += lf["size"]
    for b in blocks:
        if b["n"] > 1:
            b["name"] = b["fam"] + "*"
        cats = collections.Counter()
        for si in b["secs"]:
            cats.update(sec_cats[si])
        b["cat"] = cats.most_common(1)[0][0] if cats else CAT["config"]

    def region_at(addr):
        ri = rix[addr // 2] if addr // 2 < len(rix) else -1
        if ri < 0:
            return "", False
        return regions[ri]["name"], regions[ri]["kind"] == "config"

    grouped = [b for b in blocks if b["n"] > 1]
    events = [(b["start"], 0, b) for b in blocks] + [(a, 1, (a, l, c)) for a, l, c, lf in runs if lf < 0]
    rows = []
    for start, kind, obj in sorted(events, key=lambda e: (e[0], e[1])):
        reg, rcfg = region_at(start)
        if kind == 0:
            rows.append(dict(t="sec", name=obj["name"], n=obj["n"], start=obj["start"], end=obj["end"],
                             bytes=b3(obj["used"]), blank=b3(obj["blank"]), cat=obj["cat"], region=reg, rcfg=rcfg))
        else:
            a, l, c = obj
            if c == CAT["unmapped"] and l < 0x20:
                continue
            if any(b["start"] <= a and a + l <= b["end"] for b in grouped):
                continue            # buchi interni a una famiglia raggruppata
            rows.append(dict(t="gap", name="", n=1, start=a, end=a + l, bytes=b3(l), blank=0, cat=c, region=reg, rcfg=rcfg))
    return rows


# ----------------------------------------------------------------------------
# Output: console
# ----------------------------------------------------------------------------
def _console_mod(m):
    if m["kind"] == "lib":
        return "%s [%s]" % (re.sub(r"^.*\(|\)$", "", m["name"]), m["lib"])
    return m["name"]


def device_name(p):
    if not p:
        return ""
    if p.startswith("33") or p.startswith("30"):
        return "dsPIC" + p
    if p.startswith("24"):
        return "PIC" + p
    return p


def print_summary(M, top):
    T = M["totals"]
    mp = M["mp"]
    L = loc
    pc = lambda n, d: Pct(100.0 * n / d if d else 0).fmt(LANG)
    bw = L("bytes_word")
    print()
    print(L("c_title", dev=device_name(mp["device"]) or L("c_unknown_dev"), tool=mp["tool"] or L("c_unknown_tool")))
    print("-" * 78)
    print("%-17s %10s %s   (0x000000-0x%06X, %s %s)" % (L("c_total"), fmt_int(T["flash"]), bw, T["flash_end"],
                                                      fmt_int(T["flash"] // 3), L("c_words")))
    print("%-17s %10s %s   %6s" % (L("c_used"), fmt_int(T["used"]), bw, pc(T["used"], T["flash"])))
    print("%-17s %10s %s   %6s   (%s)" % (L("c_free"), fmt_int(T["free"]), bw, pc(T["free"], T["flash"]),
                                         L("c_free_d", max=T["maxfree"], pages=T["free_pages"], page="%X" % T["page"])))
    print("%-17s %10s %s   (%s)" % (L("c_reserved"), fmt_int(T["reserved"]), bw, L("c_reserved_d")))
    print()
    print("%-32s %12s %9s" % (L("c_cat"), bw, L("c_pflash")))
    for i, cid in enumerate(CAT_IDS):
        n = M["cat_words"][i] * 3
        if n and cid != "unmapped":
            print("%-32s %12s %9s" % (L("cat_" + cid), fmt_int(n), pc(n, T["flash"])))
    print()
    print("%-54s %12s %9s" % (L("c_mods"), bw, L("c_pused")))
    for m in sorted(M["mods"], key=lambda m: -m["bytes"])[:top]:
        if m["bytes"]:
            print("%-54s %12s %9s" % (_console_mod(m)[:54], fmt_int(m["bytes"]), pc(m["bytes"], max(1, T["used"]))))
    print()
    print("%-36s %-8s %12s  %s" % (L("c_syms"), L("c_addr"), bw, L("c_module")))
    for s in sorted(M["symbols"], key=lambda s: -s["size"])[:top]:
        print("%-36s 0x%06X %11s%s  %s" % (s["name"][:36], s["addr"], fmt_int(b3(s["size"])), "~" if s["est"] else " ",
                                          _console_mod(M["mods"][s["mod"]])[:40]))
    warns = [t for lvl, t in M["diag"] if lvl == "warn"]
    if warns:
        print()
        print(L("c_warn"))
        for t in warns:
            print("  ! " + t[LANG])
    print()


# ----------------------------------------------------------------------------
# Output: HTML
# ----------------------------------------------------------------------------
def export_data(M, files):
    T = M["totals"]
    mp = M["mp"]
    hp = M["hp"]
    hex_runs = []
    if M["has_hex"]:
        w, n = 0, len(hp)
        while w < n:
            if hp[w]:
                e = w + 1
                while e < n and hp[e]:
                    e += 1
                hex_runs.append([w * 2, (e - w) * 2])
                w = e
            else:
                w += 1
    rows = (T["flash_end"] + PAGE - 1) // PAGE
    row_span = 0x800 if rows <= 180 else (0x1000 if rows <= 360 else 0x2000)
    code_cats = [CAT[c] for c in ("code_app", "code_lib", "isr", "startup")]
    return dict(
        meta=dict(device=device_name(mp["device"]), tool=mp["tool"], files=files, version=VERSION, lang=LANG,
                  generated=datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
                  flashEnd=T["flash_end"], rowSpan=row_span, page=T["page"],
                  hasElf=M["has_elf"], hasHex=M["has_hex"], models=mp["models"],
                  options=[o for o in mp["command"]
                           if (o.startswith("--") and "=" not in o) or o.startswith(("--heap", "--stack", "--fill"))]),
        totals=T,
        cats=[dict(id=cid, label=tr("cat_" + cid), bytes=M["cat_words"][i] * 3) for i, cid in enumerate(CAT_IDS)],
        regions=[dict(name=r["name"], org=r["org"], len=r["len"], kind=r["kind"], used=b3(r.get("used", 0)),
                      free=b3(r.get("free", 0)), maxfree=b3(r.get("maxfree", 0)), size=b3(r["len"]))
                 for r in M["regions"] if r["kind"] in ("program", "reset", "ivt", "config") and r["org"] < T["flash_end"]],
        secs=[[s["name"], s["lma"], s["size"]] for s in M["sections"]],
        names=M["names"],
        leaves=[[l["sec"], l["mod"], l["name"], l["addr"], l["size"]] for l in M["leaves"]],
        runs=M["runs"],
        mods=[dict(i=m["idx"], name=m["name"], full=m["full"], lib=m["lib"], kind=m["kind"],
                   wsym=m["wsym"], wref=m["wref"], bytes=m["bytes"],
                   code=sum(m["bycat"][c] for c in code_cats), const=m["bycat"][CAT["const"]],
                   other=m["bytes"] - sum(m["bycat"][c] for c in code_cats) - m["bycat"][CAT["const"]])
              for m in M["mods"] if m["bytes"]],
        syms=[[s["addr"], s["size"], s["name"], s["cat"], s["mod"], 1 if s["est"] else 0, s["type"],
               1 if s["local"] else 0, ", ".join(s["aliases"])] for s in M["symbols"]],
        layout=M["layout"],
        hexRuns=hex_runs,
        diag=[dict(level=l, text=t) for l, t in M["diag"]],
    )


def write_html(path, data):
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False).replace("</", "<\\/")
    page = HTML_TEMPLATE.replace("/*__DATA__*/null", payload) \
        .replace("__TITLE__", "Flash map " + (data["meta"]["device"] or "")) \
        .replace("__LANG__", data["meta"]["lang"])
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)


HTML_TEMPLATE = r"""<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  color-scheme: light;
  --page:#f9f9f9; --surface:#ffffff; --ink:#191919; --ink2:#666666; --line:#e7e7e7; --axis:#c2c2c2;
  --ring:rgba(11,11,11,.10); --wash:rgba(11,11,11,.04);
  --c0:#257de0; --c1:#f47230; --c2:#00b894; --c3:#f2a600; --c4:#ee7fac; --c5:#008a17; --c6:#6a4ce2; --c7:#ec4647;
  --c8:#9a9a9a; --c9:#eeeeee; --c10:#d4d4d4; --c11:#4a4a4a; --c12:#f9f9f9;
  --warn:#b45309;
}
@media (prefers-color-scheme: dark){
  :root{
    color-scheme: dark;
    --page:#0b0b0b; --surface:#191919; --ink:#efefef; --ink2:#9c9c9c; --line:#303030; --axis:#474747;
    --ring:rgba(255,255,255,.10); --wash:rgba(255,255,255,.05);
    --c0:#338ced; --c1:#e76624; --c2:#00a888; --c3:#d28e05; --c4:#e24d8b; --c5:#0aac23; --c6:#9887ef; --c7:#eb6263;
    --c8:#777777; --c9:#262626; --c10:#3a3a3a; --c11:#c9c9c9; --c12:#0b0b0b;
    --warn:#fbb315;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:20px 16px 60px}
.top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
h1{font-size:22px;margin:0 0 2px}
h2{font-size:16px;margin:0 0 10px}
.sub{color:var(--ink2);font-size:13px}
.mono,td.a,td.n,th.n{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace}
.langs{display:flex;border:1px solid var(--axis);border-radius:6px;overflow:hidden;flex:none}
.langs button{border:0;border-radius:0;background:var(--surface);color:var(--ink2);padding:4px 10px;font-size:12px;font-weight:600;letter-spacing:.03em}
.langs button+button{border-left:1px solid var(--axis)}
.langs button[aria-pressed=true]{background:var(--ink);color:var(--surface)}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;margin:12px 0 16px;font-size:13px}
nav a{color:var(--ink2);text-decoration:none;border-bottom:1px solid var(--axis)}
nav a:hover{color:var(--ink)}
section{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:16px;margin:0 0 16px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:0 0 16px}
.kpi{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:12px 14px}
.kpi .l{color:var(--ink2);font-size:12px}
.kpi .v{font-size:24px;font-weight:600;margin:2px 0}
.kpi .d{color:var(--ink2);font-size:12px}
.bar{display:flex;gap:2px;height:26px;border-radius:4px;overflow:hidden;margin:4px 0 12px}
.bar div{min-width:2px;height:100%}
.sw{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:7px;vertical-align:-1px;border:1px solid var(--ring)}
.hx{background-image:repeating-linear-gradient(45deg,var(--c11) 0 2px,var(--c9) 2px 5px)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--ink2);font-weight:500;font-size:12px;white-space:nowrap;position:sticky;top:0;background:var(--surface)}
th.s{cursor:pointer;user-select:none}
th.s:hover{color:var(--ink)}
td.n,th.n{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
td.a{white-space:nowrap}
td.w{word-break:break-all}
tr.click{cursor:pointer}
tr.click:hover td{background:var(--wash)}
tr.gap td{color:var(--ink2)}
.scroll{max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:6px}
.scroll table th{box-shadow:0 1px 0 var(--line)}
.tools{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:0 0 10px;font-size:13px;color:var(--ink2)}
input[type=search],select,button{font:inherit;color:var(--ink);background:var(--surface);border:1px solid var(--axis);border-radius:6px;padding:4px 8px}
button{cursor:pointer}
input[type=search]{min-width:240px}
.legend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:12px;color:var(--ink2);margin:0 0 10px}
#mapbox{position:relative;overflow-x:auto}
#map{display:block;cursor:crosshair}
#tip{position:fixed;z-index:10;pointer-events:none;display:none;max-width:420px;background:var(--surface);color:var(--ink);
  border:1px solid var(--axis);border-radius:8px;padding:8px 10px;font-size:12px;box-shadow:0 6px 24px rgba(0,0,0,.18)}
#tip b{font-weight:600}
#tip .k{color:var(--ink2)}
#selbar{display:none;align-items:center;gap:10px;margin:0 0 10px;padding:6px 10px;border:1px solid var(--axis);border-radius:6px;font-size:13px}
.diag li{margin:0 0 4px}
.diag li.warn{color:var(--warn)}
.small{font-size:12px;color:var(--ink2);font-weight:400}
.note{font-size:12px;color:var(--ink2);margin:-4px 0 10px}
.pill{display:inline-block;font-size:11px;color:var(--ink2);border:1px solid var(--line);border-radius:10px;padding:0 6px;margin-left:6px}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div><h1 id="title"></h1><div class="sub" id="subtitle"></div></div>
    <div class="langs" id="langs" role="group" aria-label="Language">
      <button data-l="it" title="Italiano">IT</button><button data-l="en" title="English">EN</button><button data-l="de" title="Deutsch">DE</button>
    </div>
  </div>
  <nav>
    <a href="#s-over" data-t="nav_over"></a><a href="#s-map" data-t="nav_map"></a>
    <a href="#s-layout" data-t="nav_layout"></a><a href="#s-mods" data-t="nav_mods"></a><a href="#s-syms" data-t="nav_syms"></a>
    <a href="#s-regs" data-t="nav_regs"></a><a href="#s-diag" data-t="nav_diag"></a>
  </nav>
  <div class="kpis" id="kpis"></div>

  <section id="s-over">
    <h2 data-t="h_over"></h2>
    <div class="bar" id="obar"></div>
    <table id="cattab"></table>
  </section>

  <section id="s-map">
    <h2 data-t="h_map"></h2>
    <div class="tools">
      <label><span data-t="row_a"></span> <select id="rowspan"></select> <span data-t="row_b"></span></label>
      <span data-t="map_help"></span>
    </div>
    <div class="legend" id="legend"></div>
    <div id="selbar"><span id="seltxt"></span><button id="selclr" data-t="sel_clear"></button></div>
    <div id="mapbox"><canvas id="map"></canvas></div>
  </section>

  <section id="s-layout">
    <h2 data-t="h_layout"></h2>
    <div class="note" data-t="layout_note"></div>
    <div class="scroll"><table id="laytab"></table></div>
  </section>

  <section id="s-mods">
    <h2><span data-t="h_mods"></span> <span class="small" data-t="mods_sub"></span></h2>
    <div class="tools"><input type="search" id="modq" data-tp="mod_ph"><span id="modn"></span></div>
    <div class="scroll"><table id="modtab"></table></div>
  </section>

  <section id="s-syms">
    <h2><span data-t="h_syms"></span> <span class="small" data-t="syms_sub"></span></h2>
    <div class="tools"><input type="search" id="symq" data-tp="sym_ph">
      <label><input type="checkbox" id="symapp"> <span data-t="only_app"></span></label><span id="symn"></span></div>
    <div class="scroll"><table id="symtab"></table></div>
    <div class="small" style="margin-top:8px" data-t="est_note"></div>
  </section>

  <section id="s-regs">
    <h2 data-t="h_regs"></h2>
    <table id="regtab"></table>
  </section>

  <section id="s-diag">
    <h2 data-t="h_diag"></h2>
    <ul class="diag" id="diag"></ul>
    <div class="small" id="opts"></div>
  </section>
</div>
<div id="tip"></div>

<script>
const D = /*__DATA__*/null;

/* ---------- testi dell'interfaccia: italiano, inglese, tedesco ---------- */
const UI = {
it: {
  title: "Mappa flash {0}", generated: "generato il {0}", bytes: "byte",
  nav_over: "Occupazione", nav_map: "Mappa", nav_layout: "Layout", nav_mods: "Moduli", nav_syms: "Simboli", nav_regs: "Regioni", nav_diag: "Diagnostica",
  k_total: "Flash totale", k_total_d: "{0} parole · fino a {1}", k_used: "Occupata", k_free: "Libera",
  k_maxfree: "Buco libero più grande", k_maxfree_d: "{0} pagine da {1} istruzioni del tutto libere",
  k_hex: "Programmato nell'HEX", k_hex_d: "parole con contenuto diverso da 0xFF",
  h_over: "Occupazione dell'intera flash", c_cat: "Categoria", c_bytes: "byte", c_pflash: "% flash", c_pused: "% occupato",
  h_map: "Mappa della flash", row_a: "Una riga =", row_b: "indirizzi PC", one_page: "(una pagina)",
  map_help: "Passa il mouse per il dettaglio, clic per evidenziare un simbolo o un blocco.",
  sel_clear: "Togli evidenziazione", sel_blocks: "in {0} blocchi", sel_from: "da {0}", sel_block: "Blocco {0}", sel_module: "Modulo {0}",
  tip_section: "Sezione", tip_block: "Blocco", tip_module: "Modulo", tip_symbol: "Simbolo", tip_range: "da {0} a {1}",
  tip_hex: "HEX:", tip_prog: "programmata", tip_blank: "vuota (0xFF)",
  h_layout: "Layout in ordine di indirizzo", layout_note: "Sezioni di output e buchi tra una e l'altra. Clic su una riga per evidenziarla nella mappa.",
  c_start: "Inizio", c_end: "Fine", c_section: "Sezione", c_region: "Regione", c_blank: "vuoto nell'HEX", n_sections: "{0} sezioni", reg_config: "config word",
  h_mods: "Moduli", mods_sub: "(file oggetto e membri di libreria)", mod_ph: "Filtra per nome o libreria", mods_count: "{0} moduli · {1} byte",
  c_module: "Modulo", c_origin: "Origine", c_code: "codice", c_const: "costanti", c_other: "altro", c_why: "Richiamato da (simbolo ← chi lo usa)",
  kind_app: "applicazione", kind_lib: "libreria", kind_linker: "linker", link_root: "(radice del link)",
  h_syms: "Simboli", syms_sub: "(funzioni e tabelle)", sym_ph: "Filtra per nome o modulo", only_app: "solo applicazione", syms_count: "{0} simboli · {1} byte",
  c_symbol: "Simbolo", c_addr: "Indirizzo", c_type: "Tipo", ty_F: "funzione", ty_O: "dato", ty_static: "static", alias: "alias",
  est_note: "~ = dimensione stimata dalla distanza dal simbolo successivo (il simbolo non dichiara la propria dimensione).",
  show_all: "Mostra tutte le {0} righe",
  h_regs: "Regioni di memoria flash", c_kind: "Tipo", c_usedb: "occupati", c_freeb: "liberi", c_maxfree: "buco più grande",
  rk_program: "programma", rk_reset: "reset", rk_ivt: "vector table", rk_config: "config word", cfg_group: "{0} config word ({1} … {2})",
  h_diag: "Diagnostica", warn_p: "Attenzione: ", opts: "Opzioni del linker rilevate: {0}", none: "nessuna", models: "modello codice {0}, dati {1}"
},
en: {
  title: "Flash map {0}", generated: "generated {0}", bytes: "bytes",
  nav_over: "Usage", nav_map: "Map", nav_layout: "Layout", nav_mods: "Modules", nav_syms: "Symbols", nav_regs: "Regions", nav_diag: "Diagnostics",
  k_total: "Total flash", k_total_d: "{0} words · up to {1}", k_used: "Used", k_free: "Free",
  k_maxfree: "Largest free hole", k_maxfree_d: "{0} pages of {1} instructions completely free",
  k_hex: "Programmed in the HEX", k_hex_d: "words holding something other than 0xFF",
  h_over: "Usage of the whole flash", c_cat: "Category", c_bytes: "bytes", c_pflash: "% flash", c_pused: "% of used",
  h_map: "Flash map", row_a: "One row =", row_b: "PC addresses", one_page: "(one page)",
  map_help: "Hover for details, click to highlight a symbol or a block.",
  sel_clear: "Clear highlight", sel_blocks: "in {0} blocks", sel_from: "from {0}", sel_block: "Block {0}", sel_module: "Module {0}",
  tip_section: "Section", tip_block: "Block", tip_module: "Module", tip_symbol: "Symbol", tip_range: "from {0} to {1}",
  tip_hex: "HEX:", tip_prog: "programmed", tip_blank: "empty (0xFF)",
  h_layout: "Layout by address", layout_note: "Output sections and the holes between them. Click a row to highlight it in the map.",
  c_start: "Start", c_end: "End", c_section: "Section", c_region: "Region", c_blank: "blank in HEX", n_sections: "{0} sections", reg_config: "config words",
  h_mods: "Modules", mods_sub: "(object files and library members)", mod_ph: "Filter by name or library", mods_count: "{0} modules · {1} bytes",
  c_module: "Module", c_origin: "Origin", c_code: "code", c_const: "constants", c_other: "other", c_why: "Pulled in by (symbol ← user)",
  kind_app: "application", kind_lib: "library", kind_linker: "linker", link_root: "(link root)",
  h_syms: "Symbols", syms_sub: "(functions and tables)", sym_ph: "Filter by name or module", only_app: "application only", syms_count: "{0} symbols · {1} bytes",
  c_symbol: "Symbol", c_addr: "Address", c_type: "Type", ty_F: "function", ty_O: "data", ty_static: "static", alias: "alias",
  est_note: "~ = size estimated from the distance to the next symbol (the symbol does not declare its own size).",
  show_all: "Show all {0} rows",
  h_regs: "Flash memory regions", c_kind: "Type", c_usedb: "used", c_freeb: "free", c_maxfree: "largest hole",
  rk_program: "program", rk_reset: "reset", rk_ivt: "vector table", rk_config: "config words", cfg_group: "{0} config words ({1} … {2})",
  h_diag: "Diagnostics", warn_p: "Warning: ", opts: "Linker options detected: {0}", none: "none", models: "code model {0}, data {1}"
},
de: {
  title: "Flash-Belegung {0}", generated: "erstellt am {0}", bytes: "Byte",
  nav_over: "Belegung", nav_map: "Karte", nav_layout: "Layout", nav_mods: "Module", nav_syms: "Symbole", nav_regs: "Regionen", nav_diag: "Diagnose",
  k_total: "Flash gesamt", k_total_d: "{0} Worte · bis {1}", k_used: "Belegt", k_free: "Frei",
  k_maxfree: "Größte freie Lücke", k_maxfree_d: "{0} Seiten zu {1} Befehlen vollständig frei",
  k_hex: "Im HEX programmiert", k_hex_d: "Worte mit anderem Inhalt als 0xFF",
  h_over: "Belegung des gesamten Flash", c_cat: "Kategorie", c_bytes: "Byte", c_pflash: "% Flash", c_pused: "% vom Belegten",
  h_map: "Flash-Karte", row_a: "Eine Zeile =", row_b: "PC-Adressen", one_page: "(eine Seite)",
  map_help: "Maus darüber für Details, Klick hebt ein Symbol oder einen Block hervor.",
  sel_clear: "Hervorhebung aufheben", sel_blocks: "in {0} Blöcken", sel_from: "ab {0}", sel_block: "Block {0}", sel_module: "Modul {0}",
  tip_section: "Sektion", tip_block: "Block", tip_module: "Modul", tip_symbol: "Symbol", tip_range: "von {0} bis {1}",
  tip_hex: "HEX:", tip_prog: "programmiert", tip_blank: "leer (0xFF)",
  h_layout: "Layout nach Adresse", layout_note: "Output-Sektionen und die Lücken dazwischen. Klick auf eine Zeile hebt sie in der Karte hervor.",
  c_start: "Anfang", c_end: "Ende", c_section: "Sektion", c_region: "Region", c_blank: "leer im HEX", n_sections: "{0} Sektionen", reg_config: "Config-Words",
  h_mods: "Module", mods_sub: "(Objektdateien und Bibliotheksmitglieder)", mod_ph: "Nach Name oder Bibliothek filtern", mods_count: "{0} Module · {1} Byte",
  c_module: "Modul", c_origin: "Herkunft", c_code: "Code", c_const: "Konstanten", c_other: "Sonstiges", c_why: "Eingebunden durch (Symbol ← Nutzer)",
  kind_app: "Anwendung", kind_lib: "Bibliothek", kind_linker: "Linker", link_root: "(Link-Wurzel)",
  h_syms: "Symbole", syms_sub: "(Funktionen und Tabellen)", sym_ph: "Nach Name oder Modul filtern", only_app: "nur Anwendung", syms_count: "{0} Symbole · {1} Byte",
  c_symbol: "Symbol", c_addr: "Adresse", c_type: "Typ", ty_F: "Funktion", ty_O: "Daten", ty_static: "static", alias: "Alias",
  est_note: "~ = Größe aus dem Abstand zum nächsten Symbol geschätzt (das Symbol gibt seine Größe nicht an).",
  show_all: "Alle {0} Zeilen anzeigen",
  h_regs: "Flash-Speicherregionen", c_kind: "Typ", c_usedb: "belegt", c_freeb: "frei", c_maxfree: "größte Lücke",
  rk_program: "Programm", rk_reset: "Reset", rk_ivt: "Vektortabelle", rk_config: "Config-Words", cfg_group: "{0} Config-Words ({1} … {2})",
  h_diag: "Diagnose", warn_p: "Achtung: ", opts: "Erkannte Linker-Optionen: {0}", none: "keine", models: "Code-Modell {0}, Daten {1}"
}};
const LS_KEY = 'flashmap.lang';
let L = UI[D.meta.lang] ? D.meta.lang : 'it';
try { const saved = localStorage.getItem(LS_KEY); if (UI[saved]) L = saved; } catch (e) {}
const t = (k, ...a) => { let s = UI[L][k]; if (s === undefined) s = UI.it[k] !== undefined ? UI.it[k] : k; a.forEach((v, i) => { s = s.split('{' + i + '}').join(v); }); return s; };
const tx = o => (o && typeof o === 'object') ? (o[L] !== undefined ? o[L] : o.it) : (o || '');

const $ = id => document.getElementById(id);
const esc = s => String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fi = n => String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, L === 'en' ? ',' : '.');
const hx = a => '0x' + a.toString(16).toUpperCase().padStart(6, '0');
const b3 = pc => Math.floor((pc * 3 + 1) / 2);
const pct = (n, d) => d ? (100 * n / d).toFixed(1).replace('.', L === 'en' ? '.' : ',') + '%' : '-';
const T = D.totals, CATS = D.cats, FREE = 9, RESERVED = 10, HEXONLY = 11, UNMAPPED = 12;
const catLabel = i => tx(CATS[i].label);
const css = () => { const s = getComputedStyle(document.documentElement); const o = {};
  ['surface','ink','ink2','line','axis','page'].forEach(k => o[k] = s.getPropertyValue('--' + k).trim());
  o.c = []; for (let i = 0; i <= 12; i++) o.c.push(s.getPropertyValue('--c' + i).trim()); return o; };
const swatch = i => `<span class="sw${i === HEXONLY ? ' hx' : ''}" style="${i === HEXONLY ? '' : 'background:var(--c' + i + ')'}"></span>`;

/* ---------- ricerca ---------- */
const runs = D.runs, syms = D.syms.slice().sort((a, b) => a[0] - b[0]);
function findRun(addr) { let lo = 0, hi = runs.length - 1; while (lo <= hi) { const m = (lo + hi) >> 1, r = runs[m];
  if (addr < r[0]) hi = m - 1; else if (addr >= r[0] + r[1]) lo = m + 1; else return m; } return -1; }
function findSym(addr) { let lo = 0, hi = syms.length - 1, best = -1; while (lo <= hi) { const m = (lo + hi) >> 1;
  if (syms[m][0] <= addr) { best = m; lo = m + 1; } else hi = m - 1; }
  for (let i = best; i >= 0 && i > best - 4; i--) if (addr < syms[i][0] + syms[i][1]) return syms[i]; return null; }
function inHex(addr) { const h = D.hexRuns; let lo = 0, hi = h.length - 1; while (lo <= hi) { const m = (lo + hi) >> 1;
  if (addr < h[m][0]) hi = m - 1; else if (addr >= h[m][0] + h[m][1]) lo = m + 1; else return true; } return false; }
const modById = {}; D.mods.forEach(m => modById[m.i] = m);

/* ---------- intestazione, KPI, barra, categorie ---------- */
function renderHead() {
  const title = t('title', D.meta.device || '').trim();
  document.title = title; $('title').textContent = title;
  $('subtitle').innerHTML = [D.meta.files.map, D.meta.files.elf, D.meta.files.hex].filter(Boolean).map(esc).join(' · ')
    + '<br>' + esc(D.meta.tool || '') + ' · ' + esc(t('generated', D.meta.generated));
  const kpi = (l, v, d) => `<div class="kpi"><div class="l">${esc(l)}</div><div class="v">${esc(v)}</div><div class="d">${esc(d)}</div></div>`;
  const B = ' ' + t('bytes');
  $('kpis').innerHTML =
    kpi(t('k_total'), fi(T.flash) + B, t('k_total_d', fi(T.flash / 3), hx(T.flash_end))) +
    kpi(t('k_used'), pct(T.used, T.flash), fi(T.used) + B) +
    kpi(t('k_free'), pct(T.free, T.flash), fi(T.free) + B) +
    kpi(t('k_maxfree'), fi(T.maxfree) + B, t('k_maxfree_d', T.free_pages, fi(T.page / 2))) +
    (D.meta.hasHex ? kpi(t('k_hex'), fi(D.hexRuns.reduce((s, r) => s + r[1], 0) / 2 * 3) + B, t('k_hex_d')) : '');
}
function renderOver() {
  const shown = CATS.map((c, i) => ({...c, i})).filter(c => c.bytes > 0 && c.i !== UNMAPPED);
  $('obar').innerHTML = shown.map(c => `<div title="${esc(catLabel(c.i))}: ${fi(c.bytes)} ${t('bytes')}" class="${c.i === HEXONLY ? 'hx' : ''}"
     style="flex:${c.bytes} 0 0;${c.i === HEXONLY ? '' : 'background:var(--c' + c.i + ')'}"></div>`).join('');
  $('cattab').innerHTML = `<tr><th>${t('c_cat')}</th><th class="n">${t('c_bytes')}</th><th class="n">${t('c_pflash')}</th><th class="n">${t('c_pused')}</th></tr>` +
    shown.map(c => `<tr><td>${swatch(c.i)}${esc(catLabel(c.i))}</td><td class="n">${fi(c.bytes)}</td><td class="n">${pct(c.bytes, T.flash)}</td>
      <td class="n">${(c.i <= 8 || c.i === HEXONLY) ? pct(c.bytes, T.used) : ''}</td></tr>`).join('');
  $('legend').innerHTML = shown.map(c => `<span>${swatch(c.i)}${esc(catLabel(c.i))}</span>`).join('');
}

/* ---------- mappa su canvas ---------- */
const cv = $('map'), ctx = cv.getContext('2d');
let rowSpan = D.meta.rowSpan, G = {}, sel = null, hatch = null;
function renderRowspan() { const s = $('rowspan'); s.innerHTML = '';
  [0x400, 0x800, 0x1000, 0x2000, 0x4000].forEach(v => { const o = document.createElement('option');
    o.value = v; o.textContent = '0x' + v.toString(16).toUpperCase() + (v === D.meta.page ? ' ' + t('one_page') : ''); if (v === rowSpan) o.selected = true; s.appendChild(o); }); }
$('rowspan').onchange = ev => { rowSpan = +ev.target.value; draw(); };

function geom() { const W = Math.max(640, $('mapbox').clientWidth), gut = 70, rowH = 11, gap = 2, top = 4;
  const rows = Math.ceil(T.flash_end / rowSpan); return {W, gut, rowH, gap, top, rows, plotW: W - gut - 4, H: top * 2 + rows * (rowH + gap)}; }
function span(a0, a1, fill) { ctx.fillStyle = fill; let a = a0;
  while (a < a1) { const r = Math.floor(a / rowSpan), e = Math.min(a1, (r + 1) * rowSpan);
    const x0 = G.gut + (a - r * rowSpan) / rowSpan * G.plotW, x1 = G.gut + (e - r * rowSpan) / rowSpan * G.plotW;
    ctx.fillRect(x0, G.top + r * (G.rowH + G.gap), Math.max(x1 - x0, 1), G.rowH); a = e; } }
function tick(a, color) { const r = Math.floor(a / rowSpan); if (a === r * rowSpan) return;
  ctx.fillStyle = color; ctx.fillRect(G.gut + (a - r * rowSpan) / rowSpan * G.plotW - 0.5, G.top + r * (G.rowH + G.gap), 1, G.rowH); }
function makeHatch(C) { const p = document.createElement('canvas'); p.width = p.height = 6; const c = p.getContext('2d');
  c.fillStyle = C.c[9]; c.fillRect(0, 0, 6, 6); c.strokeStyle = C.c[11]; c.lineWidth = 1.6; c.beginPath();
  c.moveTo(-1, 7); c.lineTo(7, -1); c.moveTo(-4, 4); c.lineTo(4, -4); c.moveTo(2, 10); c.lineTo(10, 2); c.stroke(); return ctx.createPattern(p, 'repeat'); }
function fillOf(C, cat) { return cat === HEXONLY ? hatch : C.c[cat]; }
function draw() { const C = css(); G = geom(); const dpr = window.devicePixelRatio || 1;
  cv.width = G.W * dpr; cv.height = G.H * dpr; cv.style.width = G.W + 'px'; cv.style.height = G.H + 'px';
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, G.W, G.H); hatch = makeHatch(C);
  ctx.font = '10px ui-monospace,Consolas,monospace'; ctx.textBaseline = 'middle'; ctx.fillStyle = C.ink2;
  const step = G.rows > 120 ? 4 : 2;
  for (let r = 0; r < G.rows; r += step) ctx.fillText(hx(r * rowSpan), 4, G.top + r * (G.rowH + G.gap) + G.rowH / 2 + 0.5);
  ctx.globalAlpha = sel ? 0.22 : 1;
  for (const r of runs) { if (r[2] === UNMAPPED) continue; span(r[0], r[0] + r[1], fillOf(C, r[2])); }
  if (!sel) { ctx.globalAlpha = 0.55; let prev = null;
    for (const r of runs) { if (prev && r[3] >= 0 && prev[3] >= 0 && r[3] !== prev[3] && r[1] / rowSpan * G.plotW >= 5) tick(r[0], C.surface); prev = r; }
    ctx.globalAlpha = 0.4; for (const s of syms) if (s[1] / rowSpan * G.plotW >= 5) tick(s[0], C.surface); }
  ctx.globalAlpha = 1;
  if (sel) for (const [a0, a1] of sel.ranges) { let i = Math.max(0, findRun(a0));
    for (; i < runs.length && runs[i][0] < a1; i++) { const r = runs[i], s0 = Math.max(a0, r[0]), s1 = Math.min(a1, r[0] + r[1]);
      if (s1 > s0 && r[2] !== UNMAPPED) span(s0, s1, r[2] === FREE || r[2] === RESERVED ? C.ink2 : fillOf(C, r[2])); } }
}
function addrAt(ev) { const b = cv.getBoundingClientRect(), x = ev.clientX - b.left, y = ev.clientY - b.top;
  const r = Math.floor((y - G.top) / (G.rowH + G.gap)); if (r < 0 || r >= G.rows || x < G.gut || x > G.gut + G.plotW) return -1;
  const a = r * rowSpan + Math.floor((x - G.gut) / G.plotW * rowSpan / 2) * 2; return a < T.flash_end ? a : -1; }
const tip = $('tip');
cv.addEventListener('mousemove', ev => { const a = addrAt(ev); if (a < 0) { tip.style.display = 'none'; return; }
  const i = findRun(a); if (i < 0) { tip.style.display = 'none'; return; } const r = runs[i], B = ' ' + t('bytes');
  let h = `<b>${hx(a)}</b> <span class="k">· ${esc(catLabel(r[2]))}</span>`;
  if (r[3] >= 0) { const lf = D.leaves[r[3]], sec = D.secs[lf[0]], m = modById[lf[1]];
    h += `<br><span class="k">${t('tip_section')}</span> ${esc(sec[0])} <span class="k">@${hx(sec[1])}, ${fi(b3(sec[2]))}${B}</span>`;
    h += `<br><span class="k">${t('tip_block')}</span> ${esc(D.names[lf[2]])} <span class="k">@${hx(lf[3])}, ${fi(b3(lf[4]))}${B}</span>`;
    if (m) h += `<br><span class="k">${t('tip_module')}</span> ${esc(m.name)}`;
    const s = findSym(a); if (s) h += `<br><span class="k">${t('tip_symbol')}</span> <b>${esc(s[2])}</b> <span class="k">+0x${(a - s[0]).toString(16)}, ${s[5] ? '~' : ''}${fi(b3(s[1]))}${B}</span>`;
  } else h += `<br><span class="k">${t('tip_range', hx(r[0]), hx(r[0] + r[1] - 2))}, ${fi(b3(r[1]))}${B}</span>`;
  if (D.meta.hasHex) h += `<br><span class="k">${t('tip_hex')}</span> ${inHex(a) ? t('tip_prog') : t('tip_blank')}`;
  tip.innerHTML = h; tip.style.display = 'block';
  const tw = tip.offsetWidth, th = tip.offsetHeight; let x = ev.clientX + 14, y = ev.clientY + 14;
  if (x + tw > innerWidth - 8) x = ev.clientX - tw - 14; if (y + th > innerHeight - 8) y = ev.clientY - th - 14;
  tip.style.left = Math.max(4, x) + 'px'; tip.style.top = Math.max(4, y) + 'px'; });
cv.addEventListener('mouseleave', () => tip.style.display = 'none');
cv.addEventListener('click', ev => { const a = addrAt(ev); const i = a < 0 ? -1 : findRun(a);
  if (i < 0 || runs[i][3] < 0) { select(null); return; } const s = findSym(a);
  if (s) selectSym(s, false); else { const lf = D.leaves[runs[i][3]];
    select({label: () => t('sel_block', D.names[lf[2]] + ' @' + hx(lf[3])), ranges: [[lf[3], lf[3] + lf[4]]]}, false); } });
function renderSel() { const bar = $('selbar'); if (!sel) { bar.style.display = 'none'; return; }
  const tot = sel.ranges.reduce((n, r) => n + r[1] - r[0], 0); bar.style.display = 'flex';
  $('seltxt').innerHTML = '<b>' + esc(sel.label()) + '</b> · ' + fi(b3(tot)) + ' ' + t('bytes') +
    (sel.ranges.length > 1 ? ' ' + t('sel_blocks', sel.ranges.length) : '') + ' · ' + t('sel_from', hx(sel.ranges[0][0])); }
function select(s, scroll) { sel = s; renderSel();
  if (s && scroll) { const r = Math.floor(s.ranges[0][0] / rowSpan), y = cv.getBoundingClientRect().top + scrollY + G.top + r * (G.rowH + G.gap);
    scrollTo({top: Math.max(0, y - innerHeight / 3), behavior: 'smooth'}); }
  draw(); }
function selectSym(s, scroll) { select({label: () => s[2], ranges: [[s[0], s[0] + s[1]]]}, scroll); }
function selectMod(m) { const rs = []; for (const r of runs) if (r[3] >= 0 && D.leaves[r[3]][1] === m.i) rs.push([r[0], r[0] + r[1]]);
  if (rs.length) select({label: () => t('sel_module', m.name), ranges: rs}, true); }
$('selclr').onclick = () => select(null);
addEventListener('resize', draw);
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);

/* ---------- diagnostica ---------- */
function renderDiag() {
  $('diag').innerHTML = D.diag.map(d => `<li class="${d.level}">${d.level === 'warn' ? esc(t('warn_p')) : ''}${esc(tx(d.text))}</li>`).join('');
  $('opts').textContent = t('opts', D.meta.options.join(' ') || t('none'))
    + (D.meta.models.code ? ' · ' + t('models', D.meta.models.code, D.meta.models.data || '?') : '');
}

/* ---------- layout ---------- */
const layName = r => r.t === 'gap' ? catLabel(r.cat) : (r.n > 1 ? r.name + ' (' + t('n_sections', r.n) + ')' : r.name);
function renderLayout() {
  $('laytab').innerHTML = `<tr><th>${t('c_start')}</th><th>${t('c_end')}</th><th>${t('c_section')}</th><th>${t('c_region')}</th><th class="n">${t('c_bytes')}</th><th class="n">${t('c_pflash')}</th>` +
    (D.meta.hasHex ? `<th class="n">${t('c_blank')}</th>` : '') + '</tr>' +
    D.layout.map((r, i) => `<tr class="click ${r.t === 'gap' ? 'gap' : ''}" data-i="${i}"><td class="a">${hx(r.start)}</td><td class="a">${hx(r.end - 2)}</td>
      <td>${swatch(r.cat)}${esc(layName(r))}</td><td>${esc(r.rcfg ? t('reg_config') : r.region)}</td><td class="n">${fi(r.bytes)}</td><td class="n">${pct(r.bytes, T.flash)}</td>
      ${D.meta.hasHex ? `<td class="n">${r.blank ? fi(r.blank) : ''}</td>` : ''}</tr>`).join('');
}
$('laytab').addEventListener('click', ev => { const tr = ev.target.closest('tr[data-i]'); if (!tr) return; const r = D.layout[+tr.dataset.i];
  select({label: () => layName(r), ranges: [[r.start, r.end]]}, true); });

/* ---------- tabelle ordinabili ---------- */
function sortable(tab, cols, getRows, onRow, limit) { let key = cols.find(c => c.def).k, dir = -1, all = false;
  function render() { let rows = getRows().slice(); const col = cols.find(c => c.k === key);
    rows.sort((a, b) => { const x = a[key], y = b[key]; return (col.num ? x - y : String(x).localeCompare(String(y))) * dir; });
    const total = rows.length; if (!all && limit && rows.length > limit) rows = rows.slice(0, limit);
    tab.innerHTML = '<tr>' + cols.map(c => `<th class="s ${c.num ? 'n' : ''}" data-k="${c.k}">${esc(t(c.label))}${c.k === key ? (dir < 0 ? ' ▾' : ' ▴') : ''}</th>`).join('') + '</tr>' +
      rows.map((r, i) => `<tr class="click" data-i="${i}">` + cols.map(c => `<td class="${c.cls || (c.num ? 'n' : '')}">${c.fmt ? c.fmt(r[c.k], r) : esc(r[c.k])}</td>`).join('') + '</tr>').join('') +
      (total > rows.length ? `<tr><td colspan="${cols.length}"><button data-all="1">${esc(t('show_all', fi(total)))}</button></td></tr>` : '');
    tab._rows = rows; }
  tab.addEventListener('click', ev => { const th = ev.target.closest('th[data-k]'); if (th) { const k = th.dataset.k; if (k === key) dir = -dir; else { key = k; dir = cols.find(c => c.k === k).num ? -1 : 1; } render(); return; }
    if (ev.target.dataset.all) { all = true; render(); return; } const tr = ev.target.closest('tr[data-i]'); if (tr && onRow) onRow(tab._rows[+tr.dataset.i]); });
  return render; }

let modRows = [], symRows = [];
function buildRows() {
  modRows = D.mods.map(m => ({...m, kindl: t('kind_' + m.kind) + (m.lib ? ' · ' + m.lib : ''), share: m.bytes / T.used,
    why: m.wsym ? m.wsym + ' ← ' + (m.wref || t('link_root')) : ''}));
  symRows = D.syms.map(s => ({addr: s[0], pc: s[1], bytes: b3(s[1]), name: s[2], cat: s[3], catl: catLabel(s[3]), mod: (modById[s[4]] || {}).name || '',
    kind: (modById[s[4]] || {}).kind, est: s[5], type: [s[6] === '-' ? '' : t('ty_' + s[6]), s[7] ? t('ty_static') : ''].filter(Boolean).join(' '), aliases: s[8], raw: s}));
}
const renderMods = sortable($('modtab'), [
  {k: 'name', label: 'c_module', cls: 'w', fmt: (v, r) => `<span title="${esc(r.full)}">${esc(v)}</span>`},
  {k: 'kindl', label: 'c_origin'},
  {k: 'bytes', label: 'c_bytes', num: 1, def: 1, fmt: fi}, {k: 'share', label: 'c_pused', num: 1, fmt: v => pct(v, 1)},
  {k: 'code', label: 'c_code', num: 1, fmt: v => v ? fi(v) : ''}, {k: 'const', label: 'c_const', num: 1, fmt: v => v ? fi(v) : ''},
  {k: 'other', label: 'c_other', num: 1, fmt: v => v ? fi(v) : ''},
  {k: 'why', label: 'c_why', cls: 'w small'}],
  () => { const q = $('modq').value.toLowerCase(); const rows = q ? modRows.filter(m => (m.name + ' ' + m.kindl + ' ' + m.why).toLowerCase().includes(q)) : modRows;
    $('modn').textContent = t('mods_count', fi(rows.length), fi(rows.reduce((s, m) => s + m.bytes, 0))); return rows; }, selectMod, 150);
$('modq').oninput = () => renderMods();
const renderSyms = sortable($('symtab'), [
  {k: 'name', label: 'c_symbol', cls: 'w', fmt: (v, r) => esc(v) + (r.aliases ? `<span class="pill" title="${esc(r.aliases)}">${esc(t('alias'))}</span>` : '')},
  {k: 'addr', label: 'c_addr', num: 1, cls: 'a', fmt: hx},
  {k: 'bytes', label: 'c_bytes', num: 1, def: 1, fmt: (v, r) => (r.est ? '~' : '') + fi(v)},
  {k: 'catl', label: 'c_cat', fmt: (v, r) => swatch(r.cat) + esc(v)},
  {k: 'type', label: 'c_type'}, {k: 'mod', label: 'c_module', cls: 'w'}],
  () => { const q = $('symq').value.toLowerCase(), app = $('symapp').checked;
    const rows = symRows.filter(s => (!app || s.kind === 'app') && (!q || (s.name + ' ' + s.mod + ' ' + s.aliases).toLowerCase().includes(q)));
    $('symn').textContent = t('syms_count', fi(rows.length), fi(rows.reduce((s, r) => s + r.bytes, 0))); return rows; },
  r => selectSym(r.raw, true), 200);
$('symq').oninput = () => renderSyms(); $('symapp').onchange = () => renderSyms();

function renderRegs() { const big = D.regions.filter(r => r.kind !== 'config'), cfg = D.regions.filter(r => r.kind === 'config');
  const rows = big.map(r => ({...r, label: r.name}));
  if (cfg.length) rows.push({label: t('cfg_group', cfg.length, cfg[0].name, cfg[cfg.length - 1].name), kind: 'config',
    org: Math.min(...cfg.map(r => r.org)), len: Math.max(...cfg.map(r => r.org + r.len)) - Math.min(...cfg.map(r => r.org)),
    size: cfg.reduce((s, r) => s + r.size, 0), used: cfg.reduce((s, r) => s + r.used, 0), free: cfg.reduce((s, r) => s + r.free, 0), maxfree: 0});
  rows.sort((a, b) => a.org - b.org);
  $('regtab').innerHTML = `<tr><th>${t('c_region')}</th><th>${t('c_kind')}</th><th>${t('c_start')}</th><th>${t('c_end')}</th><th class="n">${t('c_bytes')}</th><th class="n">${t('c_usedb')}</th><th class="n">%</th><th class="n">${t('c_freeb')}</th><th class="n">${t('c_maxfree')}</th></tr>` +
    rows.map(r => `<tr><td>${esc(r.label)}</td><td>${esc(t('rk_' + r.kind))}</td><td class="a">${hx(r.org)}</td><td class="a">${hx(r.org + r.len - 2)}</td><td class="n">${fi(r.size)}</td>
      <td class="n">${fi(r.used)}</td><td class="n">${pct(r.used, r.size)}</td><td class="n">${fi(r.free)}</td><td class="n">${r.maxfree ? fi(r.maxfree) : ''}</td></tr>`).join(''); }

/* ---------- lingua ---------- */
function applyLang(l, save) { if (!UI[l]) return; L = l;
  if (save) { try { localStorage.setItem(LS_KEY, l); } catch (e) {} }
  document.documentElement.lang = l;
  document.querySelectorAll('#langs button').forEach(b => b.setAttribute('aria-pressed', b.dataset.l === l ? 'true' : 'false'));
  document.querySelectorAll('[data-t]').forEach(el => { el.textContent = t(el.dataset.t); });
  document.querySelectorAll('[data-tp]').forEach(el => { el.placeholder = t(el.dataset.tp); });
  renderHead(); renderOver(); renderRowspan(); renderDiag(); renderLayout(); buildRows(); renderMods(); renderSyms(); renderRegs(); renderSel(); }
$('langs').addEventListener('click', ev => { const b = ev.target.closest('button[data-l]'); if (b) applyLang(b.dataset.l, true); });

applyLang(L, false);
draw();
</script>
</body>
</html>
"""


# ----------------------------------------------------------------------------
# Riga di comando
# ----------------------------------------------------------------------------
def discover(inputs):
    found = {"map": None, "elf": None, "hex": None}
    pool = {"map": [], "elf": [], "hex": []}
    for p in inputs:
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules")]
                for fn in files:
                    ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
                    if ext in pool:
                        pool[ext].append(os.path.join(root, fn))
        elif os.path.isfile(p):
            ext = p.rsplit(".", 1)[-1].lower() if "." in p else ""
            if ext in found:
                found[ext] = p
            else:
                die("e_what", path=p)
        else:
            die("e_missing", path=p)

    def rank(path):
        low = path.replace("\\", "/").lower()
        return ("production" in low, "debug" not in low, os.path.getmtime(path))

    if not found["map"] and pool["map"]:
        found["map"] = max(pool["map"], key=rank)
    if found["map"]:
        stem = found["map"][:-4]
        for ext in ("elf", "hex"):
            if not found[ext]:
                same = [p for p in pool[ext] if p[:-4] == stem]
                if same:
                    found[ext] = same[0]
                elif pool[ext]:
                    found[ext] = max(pool[ext], key=rank)
    return found


def main(argv=None):
    global LANG
    ap = argparse.ArgumentParser(
        description="Mappa dettagliata dell'occupazione flash per dsPIC33/PIC24 da .map + .elf + .hex (XC16 / XC-DSC).")
    ap.add_argument("inputs", nargs="+", help="file .map, .elf, .hex in qualsiasi ordine, oppure la cartella del progetto")
    ap.add_argument("-o", "--out", default="flashmap.html", help="report HTML da scrivere (default: flashmap.html)")
    ap.add_argument("--lang", choices=LANGS, default="it",
                    help="lingua iniziale del report e dei messaggi a terminale: it, en, de (default it); "
                         "nel report si cambia comunque dalla pagina")
    ap.add_argument("--json", help="salva anche i dati dell'analisi in JSON (utile per confrontare due build)")
    ap.add_argument("--top", type=int, default=15, help="righe nelle classifiche stampate a terminale (default 15)")
    ap.add_argument("--flash-end", type=lambda s: int(s, 0), default=0,
                    help="primo indirizzo PC oltre la flash; di norma ricavato dal .map (es. 0x2C000)")
    ap.add_argument("--flash-region", action="append", default=[], metavar="NOME",
                    help="tratta come flash una regione del .gld che lo script non riconosce (ripetibile)")
    ap.add_argument("--ram-region", action="append", default=[], metavar="NOME",
                    help="tratta come RAM una regione del .gld (ripetibile)")
    args = ap.parse_args(argv)
    LANG = args.lang
    for stream in (sys.stdout, sys.stderr):      # console Windows: niente errori sui caratteri non ASCII
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    files = discover(args.inputs)
    if not files["map"]:
        die("e_no_map")
    print("MAP: %s" % files["map"])
    print("ELF: %s" % (files["elf"] or loc("c_notgiven")))
    print("HEX: %s" % (files["hex"] or loc("c_notgiven")))

    mp = parse_map(files["map"])
    if not mp["osecs"]:
        die("e_bad_map")
    elf = Elf(files["elf"]) if files["elf"] else None
    hexw = parse_hex(files["hex"]) if files["hex"] else None

    M = build_model(mp, elf, hexw, args)
    print_summary(M, args.top)

    data = export_data(M, {k: os.path.basename(v) if v else "" for k, v in files.items()})
    write_html(args.out, data)
    print(loc("c_report", path=os.path.abspath(args.out)))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        print(loc("c_json", path=os.path.abspath(args.json)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

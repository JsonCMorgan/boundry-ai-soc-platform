"""
Net-for-SOC lesson bank :  Show-me sections, Help-me practice, Prove-it quizzes.

Voice: .cursor/rules/tutor-professor-voice.mdc
Outline: docs/net-for-soc-outline.md
Original Boundry content only. SOC-focused, not CCNA.
"""

from __future__ import annotations

import textwrap
from typing import Any


def _b(text: str) -> str:
    """Normalize indented multi-line lesson body text."""
    return textwrap.dedent(text).strip()


def _mc(
    prompt: str,
    choices: list[str],
    answer_idx: int,
    hint: str,
    explain: str,
) -> dict[str, Any]:
    """One Help-me multiple-choice item."""
    return {
        "prompt": prompt.strip(),
        "choices": choices,
        "answer_idx": answer_idx,
        "hint": hint.strip(),
        "explain": explain.strip(),
    }


def _qz(
    q: str,
    choices: list[str],
    answer_idx: int,
    explain: str,
) -> dict[str, Any]:
    """One Prove-it quiz item (answer letter filled later)."""
    return {
        "q": q.strip(),
        "choices": choices,
        "answer_idx": answer_idx,
        "explain": explain.strip(),
    }


LESSONS: list[dict[str, Any]] = []
PRACTICE: dict[str, list[dict[str, Any]]] = {}
QUIZZES: dict[str, list[dict[str, Any]]] = {}


def _add(
    lid: str,
    order: int,
    title: str,
    minutes: int,
    goal: str,
    key_terms: list[str],
    sections: list[tuple[str, str]],
    practice: list[dict[str, Any]],
    quiz: list[dict[str, Any]],
    job_ctas: list[dict[str, str]] | None = None,
) -> None:
    """Register one ordered lesson with practice and quiz banks."""
    LESSONS.append({
        "id": lid,
        "order": order,
        "title": title,
        "minutes": minutes,
        "goal": goal,
        "key_terms": key_terms,
        "sections": [{"heading": h, "body": _b(b)} for h, b in sections],
        "job_ctas": job_ctas or [],
        "accent": "#34d399",
    })
    PRACTICE[lid] = [
        {**p, "id": f"np{order}{chr(ord('a') + i)}"}
        for i, p in enumerate(practice)
    ]
    QUIZZES[lid] = [
        {
            "id": f"nq{order}{chr(ord('a') + i)}",
            "q": item["q"],
            "choices": item["choices"],
            "answer": "ABCD"[int(item["answer_idx"])],
            "explain": item["explain"],
        }
        for i, item in enumerate(quiz)
    ]


# ── 1. Why SOC analysts need networking ──────────────────────────────────────
_add(
    "n01_why_net", 1,
    "Why SOC analysts need networking",
    15,
    "Explain why a ticket that only says \"suspicious traffic\" fails, and what network facts L1 must cite.",
    ["SOC", "Tier-1", "Ticket", "Port", "Protocol", "Evidence"],
    [
        ("What this course is (and is not)", """
            You are learning networking for a Security Operations Center job. A Security
            Operations Center, or SOC, is the team that watches alerts and investigates
            whether something bad is happening on the company network. Tier-1 (often written
            L1) is the first-line analyst who opens the alert, gathers facts, and either
            closes it with a clear note or escalates it to a more senior analyst.

            This is an analyst networking course. It is SOC-focused. It is not a CCNA
            (Cisco Certified Network Associate) course. You will not design subnets, configure
            routers, or memorize OSPF. You will learn the network facts Tier-1 cites in tickets:
            which port and protocol showed up, what a DNS name or HTTP status proves, which
            direction the traffic went, and what to do next.

            A ticket is the written record of your investigation (ServiceNow, Jira, or a
            Boundry Portfolio case). Your teammate on the next shift should understand the
            story from your note alone.
            """),
        ("Where you see this at work", """
            An alert fires: "Suspicious outbound connection." The only detail is a workstation
            IP. If you paste "looks bad" into the ticket and close it, the next analyst has to
            start over. If you write that WS-HR-03 reached 198.51.100.77 on TCP destination
            port 4444, that DNS earlier resolved update.c0ntoso-finance.com, and that the
            proxy returned HTTP status 200 for a download, the next analyst can enrich or
            escalate in minutes.

            In SOC terms, that is evidence: facts from logs that support a decision. A port
            is a number on a host that names which service is talking (example: 443 often
            means HTTPS). A protocol is the language of the packet (TCP, UDP, DNS, HTTP).
            You cite both when you have them.
            """),
        ("Technical specifics :  what L1 must cite", """
            Minimum network facts for most traffic alerts:
              1. Source host or IP (who started it)
              2. Destination IP or name (where it went)
              3. Destination port and protocol (what service shape)
              4. Direction: outbound to internet, internal-to-internal, or inbound
              5. Outcome if present: ALLOW/DENY, HTTP status, bytes transferred

            Desk clues by tool:
              - Firewall / NetFlow: src, dst, proto, sport, dport, action
              - DNS log: query name, query type (A/AAAA), client IP, answer IP
              - Proxy / web: user, method, URL or SNI/host, status, bytes
              - EDR alone is not enough for "which port" unless it also shows the connection

            Worked example: alert says rare port. You open the firewall line:
              src=10.20.30.55 dst=198.51.100.77 proto=TCP dport=4444 action=ALLOW
            Ticket Subject: WS 10.20.30.55 → 198.51.100.77 TCP/4444 ALLOW.
            What: first seen outbound on uncommon port. Why: port 4444 is a classic
            tool/listener pattern worth enriching. Next: reverse DNS / intel on dst, check
            process on host if EDR available. You did not invent malware. You cited facts.

            How to answer on the desk (and in interviews):
              1. Open the network artifact first (firewall, proxy, DNS).
              2. Write src, dst, dport/proto before any opinion.
              3. Add direction in plain words (egress vs east-west).
              4. Only then say enrich, escalate, or close with reason.

            Common trap: treating "port 443" as proof of malware. HTTPS is normal web
            traffic. Port alone is a clue. Pair it with destination reputation, URL/SNI,
            user, process, and volume.

            Remember: tickets need network nouns (host, IP, port, protocol, direction),
            not vibes.
            """),
    ],
    [
        _mc(
            "A Tier-1 ticket for a traffic alert should usually include which set of facts?",
            [
                "Only the word \"suspicious\" and the analyst's gut feel",
                "Source, destination, destination port/protocol, and direction when known",
                "Only the MAC address of the switch uplink",
                "Only the user's favorite browser theme",
            ],
            1,
            "Think about what the next shift needs to continue.",
            "Correct. Cite src, dst, dport/protocol, and direction. Common trap: closing with "
            "\"suspicious\" and no nouns. Remember: network nouns, not vibes.",
        ),
        _mc(
            "Why is this track not a CCNA course?",
            [
                "Because SOC Tier-1 needs ticket-ready network facts, not router design labs",
                "Because ports do not matter in a SOC",
                "Because DNS never appears before downloads",
                "Because firewalls never log destination ports",
            ],
            0,
            "What does L1 actually write in tickets?",
            "Correct. Analyst networking is SOC-focused: ports, DNS, HTTP, direction. "
            "Common trap: thinking you must finish CCNA before citing TCP/3389. "
            "Remember: cite what the log shows.",
        ),
    ],
    [
        _qz(
            "In Boundry terms, Tier-1 (L1) primarily means:",
            [
                "The first-line SOC analyst who gathers facts and escalates or closes",
                "The person who designs BGP for the whole ISP",
                "A Cisco switch certification only",
                "A malware family name",
            ],
            0,
            "Correct. L1 opens alerts and writes ticket facts. Common trap: equating networking "
            "study with router certifications. Remember: SOC first-line = Tier-1.",
        ),
        _qz(
            "Which ticket note is strongest for a rare outbound port alert?",
            [
                "Looks bad, closing",
                "10.20.30.55 → 198.51.100.77 TCP/4444 ALLOW; enrich dst; check host process",
                "User seemed nervous on Teams",
                "Port numbers are irrelevant",
            ],
            1,
            "Correct. You cited src, dst, port, protocol, action, and next steps. "
            "Common trap: opinion without artifacts. Remember: nouns first.",
        ),
        _qz(
            "Port 443 alone proves:",
            [
                "Confirmed ransomware",
                "Confirmed phishing click with payload",
                "Likely HTTPS/web shape; not malware by itself",
                "That DNS failed",
            ],
            2,
            "Correct. 443 usually means HTTPS. Malware needs more evidence. "
            "Common trap: port equals guilt. Remember: port is a clue, not a verdict.",
        ),
    ],
)

# ── 2. Hosts, IPs, private vs public ──────────────────────────────────────────
_add(
    "n02_hosts_ips", 2,
    "Hosts, IPs, and private vs public",
    16,
    "Read source/destination IPs and tell whether they look internal (private) or internet-facing (public).",
    ["Host", "IP address", "Private IP", "Public IP", "Source", "Destination"],
    [
        ("Define the pieces on the wire", """
            A host is any device on the network that can send or receive traffic: a laptop,
            a server, a phone, a firewall. An IP address is the number address that routers
            use to deliver packets to that host (example: 10.20.30.55). In logs you will see
            source (src) as who started the conversation and destination (dst) as who was
            contacted.

            Private IP addresses are reserved for use inside an organization. They are not
            meant to be reachable as unique addresses on the public internet. Common private
            ranges you will see every day:
              - 10.0.0.0 to 10.255.255.255
              - 172.16.0.0 to 172.31.255.255
              - 192.168.0.0 to 192.168.255.255

            Public IP addresses are routable on the internet. Example documentation ranges
            you will see in Boundry labs (safe fake internet): 198.51.100.x, 203.0.113.x.
            Real public IPs look similar but belong to ISPs and cloud providers.
            """),
        ("Where you see this at work", """
            Your SIEM (security log system) shows src=10.20.30.12 dst=198.51.100.77. You
            immediately know: an internal host talked to something that looks internet-facing.
            If both ends are 10.x or 192.168.x, you are looking at internal-to-internal traffic.

            In SOC terms, private vs public is the first filter for direction. You still confirm
            with your environment map (VPN pools, guest Wi-Fi, cloud VNets), but the private
            ranges are the default mental model.
            """),
        ("Technical specifics", """
            Reading order for every flow line:
              1. Circle src and dst
              2. Ask: private or public for each?
              3. Note hostnames if present (WS-HR-03, PROD-DC01)
              4. Do not assume the hostname is trustworthy if an attacker set it; still cite IP

            Special cases Tier-1 hits:
              - NAT (Network Address Translation): many internal hosts share one public IP
                when they leave. Firewall logs may show the internal src before NAT and the
                public src after. Cite what the log field actually shows.
              - VPN clients often get private IPs from a pool (example: 10.99.0.0/16). They
                still count as "internal" for east-west vs egress decisions once connected.
              - Link-local 169.254.x.x usually means failed DHCP, not internet C2 by itself.

            Worked example:
              Line A: src=10.20.30.12 dst=10.20.30.77 → both private → internal conversation
              Line B: src=10.20.30.12 dst=203.0.113.88 → private to documentation public → egress shape
              Line C: src=198.51.100.9 dst=10.20.30.5 → public to private → ingress shape (internet in)

            How to answer:
              1. Label each IP private or public.
              2. Write both ends in the ticket.
              3. Only then name direction (covered deeply in a later lesson).

            Common trap: calling any 172.x address private. Only 172.16.0.0 through
            172.31.255.255 is private. 172.32.x.x is public space.

            Remember: private ranges are your quick internal vs internet compass.
            """),
    ],
    [
        _mc(
            "src=10.20.30.55 dst=198.51.100.77 :  how should you describe the ends?",
            [
                "Both public internet hosts",
                "Source looks private/internal; destination looks public/internet-facing",
                "Both are always domain controllers",
                "Destination is always DNS",
            ],
            1,
            "Recall the 10.x private range and documentation public ranges.",
            "Correct. 10.x is private; 198.51.100.x is a public documentation range. "
            "Common trap: treating every IP as internal. Remember: private vs public first.",
        ),
        _mc(
            "Which range is private?",
            [
                "8.8.8.8",
                "192.168.40.12",
                "198.51.100.1",
                "1.1.1.1",
            ],
            1,
            "One of these is a home/office style private range.",
            "Correct. 192.168.x.x is private. Common trap: assuming all 198.x is private. "
            "Remember: 10/8, 172.16-31, 192.168/16.",
        ),
    ],
    [
        _qz(
            "In a firewall log, \"src\" usually means:",
            [
                "The packet's starting host/IP",
                "The antivirus signature name",
                "The ticket severity only",
                "The user's job title",
            ],
            0,
            "Correct. Source is who started the conversation. Common trap: swapping src and dst. "
            "Remember: src starts, dst is contacted.",
        ),
        _qz(
            "Both src and dst are 10.20.40.x. Best first label:",
            [
                "Confirmed internet egress",
                "Looks internal-to-internal (both private)",
                "Confirmed inbound from Tor",
                "DNS failure only",
            ],
            1,
            "Correct. Two private IPs suggest internal conversation. Common trap: calling any "
            "TCP session \"egress.\" Remember: both private ≈ internal path.",
        ),
        _qz(
            "Which statement about 172.x addresses is true?",
            [
                "Every 172.x.x.x address is private",
                "Only 172.16.0.0-172.31.255.255 is the private block in that space",
                "172.x never appears in enterprise networks",
                "172.x always means public cloud DNS",
            ],
            1,
            "Correct. The private slice is 172.16-172.31. Common trap: marking 172.32 as private. "
            "Remember: 16 through 31 only.",
        ),
    ],
)

# ── 3. TCP, UDP, connections ──────────────────────────────────────────────────
_add(
    "n03_tcp_udp", 3,
    "TCP, UDP, and connections",
    16,
    "Distinguish TCP vs UDP for ticket language, and say what a destination port names.",
    ["TCP", "UDP", "ICMP", "Destination port", "Source port", "Connection"],
    [
        ("Protocols in plain English", """
            A protocol is the rule set for how two hosts exchange data. The two transport
            protocols you will cite constantly are TCP and UDP.

            TCP (Transmission Control Protocol) builds a connection, checks that data arrived,
            and retransmits if needed. Remote desktop, file shares, and most web traffic use
            TCP. When a log says proto=TCP, think "connection-oriented session."

            UDP (User Datagram Protocol) sends datagrams without that full connection setup.
            DNS queries often use UDP. Voice and some VPN tunnels use UDP. When a log says
            proto=UDP, do not invent a TCP handshake story.

            ICMP (Internet Control Message Protocol) is for control messages like ping. You
            may see it in scans. It does not use port numbers the same way TCP/UDP do.
            """),
        ("Where you see this at work", """
            A junior note says "UDP 3389 lateral movement." That is almost always wrong
            language. Remote Desktop Protocol (RDP) rides TCP destination port 3389. If you
            mix protocol and port, the next analyst wastes time.

            In analyst terms: destination port names the service shape on the receiver. Source
            port is usually an ephemeral high number chosen by the client (example: 51884).
            Cite destination port in tickets unless source port is the story (rare).
            """),
        ("Technical specifics", """
            Ticket habits:
              - Write TCP/3389 or UDP/53, not just "3389" when the log gives proto
              - Client source ports above ~1024 are normal; do not escalate solely on sport
              - Same destination port can appear on TCP and UDP for different services; believe
                the proto field in the log

            Common SOC pairs:
              - TCP/22 SSH, TCP/3389 RDP, TCP/445 SMB
              - TCP/80 HTTP, TCP/443 HTTPS
              - UDP/53 or TCP/53 DNS (TCP used for larger responses / zone transfers)
              - TCP/25 or TCP/587 mail submission paths

            Worked example: firewall shows sport=51884 dport=445 proto=TCP between two 10.x
            hosts. The story is SMB (file/share admin path) on TCP/445. The source port is
            just the client side of the socket. Your Subject can be short:
            "WS-A → WS-B TCP/445 ALLOW (east-west SMB shape)."

            How to answer:
              1. Read proto.
              2. Read dport.
              3. Name the usual service for that pair.
              4. Say if the pair is unusual for that host role.

            Desk picture: two alerts land one minute apart. One is UDP/53 to an internal
            resolver. One is TCP/443 to the internet. Different protocols, different stories.
            Mixing them into "suspicious ports" without proto loses the handoff. Write the
            pair every time so the next analyst does not re-open the raw log for basics.

            Common trap: calling every high destination port "ephemeral." Ephemeral ports are
            usually source ports. A destination port 4444 or 8080 can be a listener on purpose.

            Remember: protocol + destination port = the service shape you cite.
            """),
    ],
    [
        _mc(
            "RDP between two workstations should be cited as:",
            [
                "UDP/3389 by default",
                "TCP/3389 (Remote Desktop)",
                "ICMP only",
                "Source port 3389 as the service",
            ],
            1,
            "Which protocol does Remote Desktop use on the wire?",
            "Correct. RDP is TCP/3389. Common trap: writing UDP/3389. "
            "Remember: RDP = TCP/3389.",
        ),
        _mc(
            "In most client→server flows, which port names the service you cite?",
            [
                "Source port (ephemeral)",
                "Destination port",
                "The VLAN ID only",
                "The XP score",
            ],
            1,
            "Clients pick a high random source port.",
            "Correct. Destination port names the service. Common trap: escalating on sport "
            "51884 alone. Remember: cite dport.",
        ),
    ],
    [
        _qz(
            "UDP is best described as:",
            [
                "Always encrypted ransomware",
                "A transport that sends datagrams without TCP's full connection guarantees",
                "Identical to HTTPS",
                "Only used for RDP",
            ],
            1,
            "Correct. UDP is datagram-oriented. Common trap: assuming UDP means malware. "
            "Remember: DNS often uses UDP/53.",
        ),
        _qz(
            "sport=51884 dport=443 proto=TCP most likely means:",
            [
                "The service is on port 51884",
                "Client ephemeral source; HTTPS-shaped destination 443",
                "Confirmed ICMP redirect",
                "Mail submission on 25",
            ],
            1,
            "Correct. High sport is normal client side; 443 is the service. "
            "Common trap: calling 51884 the malware port. Remember: dport is the service.",
        ),
        _qz(
            "Why write \"TCP/445\" instead of only \"445\" when the log includes proto?",
            [
                "Because protocol + port reduces ambiguity for the next analyst",
                "Because UDP/445 is required for HTTPS",
                "Because tickets forbid numbers",
                "Because ICMP needs two ports",
            ],
            0,
            "Correct. Proto + port is clearer handoff language. Common trap: bare port numbers "
            "with no protocol. Remember: TCP/445 not just 445.",
        ),
    ],
)

# ── 4. Ports that matter ──────────────────────────────────────────────────────
_add(
    "n04_ports_matter", 4,
    "Ports that matter on tickets",
    18,
    "Cite the SOC shortlist (22, 3389, 445, 80/443, 53, 25/587) with the service each usually means.",
    ["SSH", "RDP", "SMB", "HTTP", "HTTPS", "DNS", "SMTP"],
    [
        ("The shortlist, defined", """
            You do not need every port in IANA's list. You need the shortlist SOC Tier-1
            actually writes in tickets. Each item below pairs a destination port with the
            service name you should say out loud.

            SSH (Secure Shell) :  TCP/22: remote admin command shell.
            RDP (Remote Desktop Protocol) :  TCP/3389: remote Windows desktop.
            SMB (Server Message Block) :  TCP/445: Windows file/share and many admin tools.
            HTTP :  TCP/80: unencrypted web.
            HTTPS :  TCP/443: encrypted web (TLS).
            DNS (Domain Name System) :  UDP/53 or TCP/53: name to IP lookup.
            SMTP / submission :  TCP/25 or TCP/587: mail transfer / mail submission.

            Non-standard high ports (examples: 4444, 8080, 8443) often mean tools, proxies,
            or reverse shells. They are not proof alone. Pair with process, destination,
            and volume.
            """),
        ("Where you see this at work", """
            Lateral movement screening often starts with unexpected TCP/3389 or TCP/445
            between workstations. Phishing follow-on often shows DNS then HTTPS. Spam bots
            sometimes show workstation → internet TCP/25. Your job is to name the service
            shape correctly so enrichment aims at the right question.

            In analyst terms: the shortlist is a vocabulary, not a guilt list. Naming the
            service tells the next person which playbook door to open (remote admin, file
            share, web fetch, mail path, or name lookup).
            """),
        ("Technical specifics", """
            Ticket one-liners that hire managers like:
              - Unexpected internet-facing TCP/22 to a jump host → verify allow-list
              - WS to WS TCP/3389 → east-west RDP, check account and change ticket
              - Burst TCP/445 across a subnet → backup vs lateral; document volume and ends
              - DNS for rare domain then TCP/443 GET 200 → name + fetch story
              - Workstation to internet TCP/25 → possible malware mailer (policy dependent)

            Worked example: alert "SMB suspicious." Snippet shows
              src=10.20.40.9 dst=10.20.40.15,10.20.40.16 proto=TCP dport=445 count=140/3m
            You write: east-west TCP/445 burst from .9 to three peers, 140 hits in 3 minutes.
            Next: host team / EDR for admin tool vs worm. You do not invent ransomware.

            How to answer:
              1. Map dport → usual service.
              2. Ask if that service is expected for this host role.
              3. Cite both ends and direction.
              4. Pick enrich vs escalate based on unexpected + volume + destination rarity.

            Say the shortlist cold before a shift: 22 SSH, 3389 RDP, 445 SMB, 80/443 web,
            53 DNS, 25/587 mail. If a port is not on that list, call it uncommon or
            application-specific and enrich. Hub flashcards in the next lesson lock the same
            facts under time pressure.

            Common trap: treating TCP/443 to a CDN as "C2" with no other evidence. Web is
            noisy. Port shortlist helps you start; it does not finish the case alone.

            Remember: 22 SSH, 3389 RDP, 445 SMB, 80/443 web, 53 DNS, 25/587 mail.
            """),
    ],
    [
        _mc(
            "TCP/3389 on a ticket usually means:",
            ["DNS lookup", "Remote Desktop (RDP)", "SMTP mail", "ICMP ping only"],
            1,
            "Which remote admin desktop port is standard on Windows?",
            "Correct. 3389 is RDP. Common trap: calling 3389 SMB. Remember: 3389 RDP, 445 SMB.",
        ),
        _mc(
            "Unexpected workstation → internet TCP/25 is worth noting because:",
            [
                "TCP/25 is always HTTPS",
                "It can indicate a spam bot or unexpected mail submission path",
                "Port 25 means RDP",
                "Port 25 is only used for DNS",
            ],
            1,
            "What service historically listens on 25?",
            "Correct. SMTP on 25 from a workstation can be malware mailer behavior. "
            "Common trap: ignoring 25 because \"email is normal.\" Remember: who should send mail?",
        ),
    ],
    [
        _qz(
            "TCP/445 most often indicates:",
            ["HTTPS web", "SMB file/share or Windows admin tooling", "SSH shell", "NTP only"],
            1,
            "Correct. 445 is SMB. Common trap: mixing 445 with 443. Remember: 445 SMB, 443 HTTPS.",
        ),
        _qz(
            "UDP/53 or TCP/53 is:",
            ["RDP", "DNS name lookup", "SMB", "Always malware"],
            1,
            "Correct. Port 53 is DNS. Common trap: calling every 53 alert C2 without the query name. "
            "Remember: cite the query name.",
        ),
        _qz(
            "Port 4444 in a firewall ALLOW to the internet should make you:",
            [
                "Close as benign with no notes",
                "Enrich destination and host process; uncommon listener port pattern",
                "Reimage every laptop in the building immediately with no evidence",
                "Assume it is always NTP",
            ],
            1,
            "Correct. Uncommon high ports deserve enrichment, not instant verdict. "
            "Common trap: malware certainty from port alone. Remember: pair port with process/dst.",
        ),
        _qz(
            "SSH remote admin shell is typically:",
            ["TCP/22", "UDP/445", "TCP/53", "ICMP/3389"],
            0,
            "Correct. SSH is TCP/22. Common trap: mixing SSH with SMB ports. Remember: 22 SSH.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net#flashcards", "label": "Hub flashcards", "why": "Drill the same shortlist"},
    ],
)

# ── 5. Port flashcards deep dive ──────────────────────────────────────────────
_add(
    "n05_port_flashcards", 5,
    "Port flashcards deep dive",
    14,
    "Drill the same port facts as flashcards until you can name service + why L1 cares.",
    ["Flashcard", "TCP/22", "TCP/3389", "TCP/445", "TCP/443", "UDP/53"],
    [
        ("How to use these cards", """
            A flashcard here is a front (port or clue) and a back (service + why Tier-1 cares).
            Say the back out loud before you reveal. The hub flashcards use the same facts.
            This lesson slows down so each card becomes ticket language, not trivia.
            """),
        ("Where you see this at work", """
            During a Quick Shift you have thirty seconds before the next alert. You need
            TCP/445 → SMB and "document both ends" without opening a search engine. That is
            what these cards train.
            """),
        ("Technical specifics :  card backs as ticket lines", """
            TCP/22 → SSH. Unexpected 22 from internet or between workstations: note allow-list
            and account. Do not confuse with 3389.

            TCP/3389 → RDP. Lateral screening starter with 445. Cite src, dst, user if known.

            TCP/445 → SMB. East-west bursts: backup, admin tools, or lateral movement. Volume
            and peer count matter.

            TCP/443 / 80 → HTTPS / HTTP. Cite URL or SNI/host when you have it. Port alone
            does not prove malware.

            UDP/TCP 53 → DNS. Rare query name before a download is classic setup evidence.

            TCP/25 / 587 → SMTP / submission. Workstation to internet:25 can mean spam bot.

            Non-standard high port (4444, 8080) → tools/proxies/listeners. Pair with process
            and destination reputation.

            HTTP 200 vs 302 → 200 body delivered; 302 redirect. Phish click with 200 means
            content was served.

            Worked example: front "TCP 445". You say: "SMB. East-west file/share or admin.
            Document both ends and volume." That sentence is already ticket-ready.

            How to practice:
              1. Run hub flashcards once without notes.
              2. Misses become a written ticket line.
              3. Retake until you can do the shortlist cold.

            Common trap: memorizing numbers without the "why L1 cares" clause. Numbers without
            judgment do not help the next shift.

            Remember: every port card ends with a ticket action (cite, enrich, or compare ends).

            Extra reps that stick under shift pressure:
              - Say the service name, then one risk sentence, then one ticket verb.
                Example: "445, SMB, east-west risk if unexpected, document both ends."
              - Pair cards that people swap: 443 vs 445, 22 vs 3389, 53 vs 25.
              - After a miss, write one Subject line using that port before you flip next.
              - When a Boundry drill snippet appears later, you should hear the card back
                in your head before you click a signal button.

            Interview framing (still not CCNA): hiring managers rarely ask you to subnet.
            They ask whether you notice odd 3389 between workstations or a workstation
            speaking SMTP to the internet. These cards are the vocabulary for that answer.
            """),
    ],
    [
        _mc(
            "Flashcard front \"TCP 22\". Best back includes:",
            [
                "HTTPS web only",
                "SSH remote admin shell; unexpected internet or workstation use deserves a note",
                "DNS query name",
                "HTTP status 302 only",
            ],
            1,
            "What service is Secure Shell?",
            "Correct. 22 is SSH with a clear L1 note. Common trap: mixing 22 with 443. "
            "Remember: 22 SSH.",
        ),
        _mc(
            "HTTP status 200 on a phish-related URL mainly tells you:",
            [
                "The page or payload response body was delivered",
                "DNS never ran",
                "The traffic was east-west SMB",
                "The port was 25",
            ],
            0,
            "What does 200 mean in HTTP?",
            "Correct. 200 means content was returned. Common trap: treating 302 the same as 200. "
            "Remember: 200 delivered, 302 redirect.",
        ),
    ],
    [
        _qz(
            "TCP/445 flashcard back should mention:",
            ["SMTP only", "SMB and documenting both ends / volume", "Only ICMP", "Always close as noise"],
            1,
            "Correct. SMB cards stress ends and volume. Common trap: \"445 = ransomware\" with no "
            "other facts. Remember: document both ends.",
        ),
        _qz(
            "UDP/TCP 53 flashcard focuses on:",
            ["RDP user sessions", "DNS name lookups before later fetches", "SMB only", "Printer ink"],
            1,
            "Correct. DNS cards highlight query names. Common trap: ignoring the name and citing "
            "only the resolver IP. Remember: cite the query name.",
        ),
        _qz(
            "A non-standard high port card (e.g. 4444) teaches you to:",
            [
                "Declare malware with certainty from the port alone",
                "Treat it as a tool/listener pattern and pair with process and destination intel",
                "Ignore it forever",
                "Rewrite it as UDP/53",
            ],
            1,
            "Correct. High ports need pairing, not panic. Common trap: instant malware label. "
            "Remember: port + process + dst.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net#flashcards", "label": "Run hub flashcards", "why": "Same cards, faster reps"},
    ],
)

# ── 6. DNS basics ─────────────────────────────────────────────────────────────
_add(
    "n06_dns_basics", 6,
    "DNS: names before downloads",
    16,
    "Explain what a DNS query proves, and why the query name often matters more than a raw IP alone.",
    ["DNS", "Query name", "Resolver", "A record", "C2"],
    [
        ("What DNS is", """
            DNS means Domain Name System. It translates a human name like login.contoso.com
            into an IP address a computer can contact. A DNS query is the ask: "what IP is
            this name?" A resolver is the server that answers. An A record answer is an IPv4
            address for that name.

            SOC often sees DNS queries before a bad download. The name can be more useful than
            the later IP, because attackers rotate IPs while keeping similar names, and because
            intel tools pivot on domains. Command and control, often shortened to C2, is the
            channel malware uses to take orders. A rare DNS name can be an early clue toward
            C2, but the query alone is not a guilty verdict.
            """),
        ("Where you see this at work", """
            Proxy shows a download from 203.0.113.88. Alone, that IP is a cold start. DNS
            thirty seconds earlier shows update.c0ntoso-finance.com typed with a zero. Now you
            have a domain to enrich and a timeline: name lookup, then fetch.

            In analyst terms: DNS is the "who did they ask for" layer. Firewall and proxy
            answer "what did they fetch." You need both for a clean ticket.
            """),
        ("Technical specifics", """
            Fields to cite from a DNS log:
              - query name (the domain asked)
              - query type (A, AAAA, MX, TXT, …)
              - client IP / host that asked
              - answer IP if logged
              - timestamp

            Desk patterns:
              - New / rare domain + immediate HTTP(S) GET with 200 bytes large → enrich domain
              - DNS to known-good CDNs alone is usually noise
              - DNS tunneling (very long odd query names, high volume) is advanced; escalate with
                samples rather than guessing encodings
              - Lookalike brands (extra letters, zero for o) deserve an exact paste into What

            Worked example:
              14:01:02 DNS query name=update.c0ntoso-finance.com type=A client=10.20.30.88
              → 203.0.113.88
            Ticket: client 10.20.30.88 resolved update.c0ntoso-finance.com to 203.0.113.88.
            Next: domain intel + look for follow-on HTTP to that IP. Do not stop at the
            resolver address. Do not rewrite the name from memory.

            How to answer:
              1. Copy the query name exactly (watch 0 vs o).
              2. Cite client host/IP.
              3. Note answer IP if present.
              4. Search for same client traffic right after the query.

            Common trap: writing only the DNS server IP (the resolver) as if it were the
            malicious destination. The resolver is often 10.x.x.53 or a cloud DNS. The story
            is usually the query name, not the resolver.

            Remember: DNS proves the name was asked; pair it with what happened next.
            """),
    ],
    [
        _mc(
            "What does a DNS query primarily prove?",
            [
                "That malware already encrypted the disk",
                "That a client asked to resolve a name (often before connecting)",
                "That TCP/445 east-west finished",
                "That the ticket can skip destination IPs forever",
            ],
            1,
            "DNS is the ask for a name→IP mapping.",
            "Correct. A query shows the name was looked up. Common trap: treating DNS as proof "
            "of infection alone. Remember: name asked, then check the fetch.",
        ),
        _mc(
            "Why cite the query name instead of only the resolver IP?",
            [
                "Resolver IPs are never logged",
                "The queried domain is usually the intel pivot; resolvers are often shared infra",
                "Query names are always IP addresses already",
                "Resolvers prove RDP",
            ],
            1,
            "Who is suspicious: 8.8.8.8 or evil-update.example?",
            "Correct. Enrich the domain. Common trap: flagging only 8.8.8.8. "
            "Remember: cite the query name.",
        ),
    ],
    [
        _qz(
            "An A record answer in DNS is typically:",
            ["An HTTP status code", "An IPv4 address for the name", "A SMB share ACL", "A CVE number"],
            1,
            "Correct. A records map names to IPv4. Common trap: calling the answer an HTTP 200. "
            "Remember: A = IPv4 answer.",
        ),
        _qz(
            "Best ticket fragment after a rare DNS lookup:",
            [
                "DNS happened",
                "10.20.30.88 queried update.c0ntoso-finance.com (A) → 203.0.113.88; checking follow-on HTTP",
                "User likes finance",
                "Port 53 means RDP",
            ],
            1,
            "Correct. Client, name, type, answer, next step. Common trap: vague \"DNS happened.\" "
            "Remember: paste the query name.",
        ),
        _qz(
            "C2 in analyst talk usually means:",
            [
                "Command and control channel for malware",
                "Cisco Core 2 exam only",
                "A private IP range",
                "HTTP status 302 only",
            ],
            0,
            "Correct. C2 is command-and-control. Common trap: labeling every rare domain as C2 "
            "without fetch/process evidence. Remember: DNS is a clue toward C2, not the verdict.",
        ),
    ],
)

# ── 7. HTTP/HTTPS status ──────────────────────────────────────────────────────
_add(
    "n07_http_status", 7,
    "HTTP/HTTPS and status codes",
    16,
    "Read method, URL/host, and status (200 vs 302 vs 403/404) as evidence of what the client got.",
    ["HTTP", "HTTPS", "TLS", "SNI", "Status code", "GET"],
    [
        ("Web traffic words", """
            HTTP is the language browsers and many tools use to fetch pages and files. HTTPS
            is HTTP inside TLS encryption (Transport Layer Security). On the wire you often
            see TCP/443 for HTTPS and TCP/80 for HTTP.

            A method is the verb: GET means "give me this resource," POST means "send data."
            A URL is the full address. Host or SNI (Server Name Indication) is the name the
            client asked for during TLS. A status code is the server's short result number:
            200 means success with a body, 302 means redirect, 403 means forbidden, 404 means
            not found.
            """),
        ("Where you see this at work", """
            Phishing investigations live or die on status. A click that returns 200 with large
            bytes means content was served. A 302 to a login portal may be a redirect chain.
            A 404 may mean the lure died. Port 443 alone never tells you which of those happened.

            In analyst terms: HTTPS on TCP/443 is the transport shape. Status and bytes are
            the outcome. Transport without outcome is an incomplete web ticket.
            """),
        ("Technical specifics", """
            Cite from proxy/web logs:
              - user (if present)
              - method + URL or host/SNI
              - dport (80/443)
              - http_status
              - bytes (size matters for downloads)
              - action ALLOW/DENY

            Status quick map for L1:
              - 200: response delivered (page or file). Pair with bytes.
              - 301/302/307: redirect. Note the Location if logged.
              - 401/403: auth/forbidden. Not proof of safety.
              - 404: missing. Lure may be down.
              - 500: server error. Still note the URL if it was a phish domain.

            Worked example:
              user=ap.clerk@clientcorp.example GET https://c0ntoso-finance.com/wire-approve
              dport=443 http_status=200 action=ALLOW bytes=482112
            Ticket: user fetched wire-approve over HTTPS, status 200, ~482KB. Next: domain
            intel + endpoint for file write / process. Port 443 is context, not the story.

            How to answer:
              1. Copy URL/host exactly.
              2. Write status and bytes.
              3. Say what 200/302 means in plain English.
              4. Do not claim "malware" from status alone.

            Compare two 200s: twelve bytes of empty HTML versus a half-megabyte executable
            path. Same status number, different urgency. Always glance at bytes before you
            close a phish-related web alert as "just a page view."

            Common trap: "DENIED" at the proxy means the user is safe forever. They may have
            used another path (cell hotspot, different proxy). DENY is evidence for that hop only.

            Remember: URL + status (+ bytes) beats port 443 alone.
            """),
    ],
    [
        _mc(
            "HTTP status 200 primarily means:",
            [
                "The request was redirected",
                "The response body was successfully delivered",
                "DNS failed",
                "The traffic was TCP/445",
            ],
            1,
            "What does success mean for HTTP?",
            "Correct. 200 delivered a response. Common trap: equating 200 with \"safe.\" "
            "Remember: 200 means delivered, not benign.",
        ),
        _mc(
            "Why is citing SNI/host useful on HTTPS?",
            [
                "Because port 443 never appears in logs",
                "Because encryption hides the URL path sometimes, but the requested name is often still visible",
                "Because SNI proves SMB lateral movement",
                "Because SNI replaces user identity always",
            ],
            1,
            "What name does TLS often expose?",
            "Correct. SNI/host gives the name when the full URL path is hidden. "
            "Common trap: saying HTTPS means no useful fields. Remember: cite host/SNI.",
        ),
    ],
    [
        _qz(
            "HTTP 302 usually indicates:",
            ["A redirect", "A DNS A record", "SMB signing", "ICMP unreachable only"],
            0,
            "Correct. 302 is redirect. Common trap: treating 302 like 200 body delivery. "
            "Remember: 302 = redirect, 200 = delivered.",
        ),
        _qz(
            "Strongest web evidence line for a phish click:",
            [
                "dport=443",
                "user + URL + status 200 + bytes",
                "proto=TCP only",
                "sport=52001 only",
            ],
            1,
            "Correct. User, URL, status, bytes tell the story. Common trap: port-only tickets. "
            "Remember: URL + status.",
        ),
        _qz(
            "A proxy DENY on one request proves:",
            [
                "The user never contacted that site by any path",
                "That hop blocked the request; other paths may still exist",
                "RDP succeeded",
                "DNS cannot run anymore",
            ],
            1,
            "Correct. DENY is per hop. Common trap: global safety from one deny. "
            "Remember: cite the hop you saw.",
        ),
    ],
)

# ── 8. DNS → HTTP path ────────────────────────────────────────────────────────
_add(
    "n08_dns_http_path", 8,
    "Following the DNS → HTTP path",
    18,
    "Chain a DNS lookup to a later HTTP(S) fetch into one timeline story for the ticket.",
    ["Timeline", "DNS then HTTP", "Pivot", "Enrichment"],
    [
        ("Build one story from two logs", """
            Enrichment means looking up reputation or context before you escalate. A pivot is
            when you take a value from one log (a domain, an IP, a user) and search for it in
            another log. The classic Tier-1 pivot is DNS query name → later HTTP(S) to the
            answer IP or same host name.

            You are not proving malware yet. You are building a timeline: at time T the host
            asked for a name; at T+seconds it fetched a URL and got a status.
            """),
        ("Where you see this at work", """
            Boundry drill shape: DNS for a lookalike finance domain, then HTTP GET of u.exe
            with status 200 and large bytes. One paragraph in the ticket beats two disconnected
            alerts.

            In analyst terms: the path is a join, not two separate vibes. You prove the same
            client asked for a name, then fetched content, within a short window.
            """),
        ("Technical specifics", """
            Timeline recipe:
              1. Sort DNS and proxy/firewall by time for the same client IP/host
              2. Match DNS answer IP to later destination IP, or match query name to Host/SNI
              3. Write three lines: DNS fact, HTTP fact, decision/next
              4. Keep clocks honest (note timezone if logs disagree)

            Matching tips:
              - Same client IP within a short window is the default join key
              - If HTTP shows only IP, DNS answer is the bridge
              - If HTTPS shows SNI, you may match query name even without answer IP in the DNS row
              - If times disagree by hours, check timezone and collector delay before inventing
                a second actor

            Worked example:
              14:01:02 DNS name=update.c0ntoso-finance.com client=10.20.30.88 → 203.0.113.88
              14:01:04 HTTP GET http://203.0.113.88/u.exe status=200 bytes=482112 host=WS-HR-03
            Ticket Subject: WS-HR-03 DNS + HTTP download update.c0ntoso-finance.com / u.exe
            What: resolved lookalike domain then fetched ~482KB with 200.
            Why: pre-exfil / malware delivery pattern worth host + intel follow-up.
            Next: EDR file create / process; domain intel; contain if policy says so.

            How to answer:
              1. Paste both timestamps.
              2. Show the join (IP or name).
              3. State status/bytes.
              4. Separate facts from hypothesis with the word "pattern" not "confirmed APT."

            Interview tip: say the join out loud. "Same host, two minutes, name then fetch."
            That sentence shows timeline thinking without claiming a nation-state.

            Common trap: reversing order and claiming HTTP caused DNS. DNS usually comes first
            for name-based fetches. Also trap: merging two different users because the domain
            matched. Join on client host/IP.

            Remember: DNS names the target; HTTP shows whether content was fetched.
            """),
    ],
    [
        _mc(
            "Best join key when chaining DNS to HTTP for one investigation:",
            [
                "Random ports only",
                "Same client host/IP in a short time window, plus answer IP or name match",
                "Only the SOC manager's name",
                "Only the XP reward value",
            ],
            1,
            "What ties two log lines to one actor?",
            "Correct. Client identity + time + IP/name bridge. Common trap: joining only on "
            "domain across different users. Remember: join on the client.",
        ),
        _mc(
            "DNS then HTTP GET 200 for u.exe is best described as:",
            [
                "Proof the disk is already encrypted",
                "A delivery-pattern timeline that deserves host and intel follow-up",
                "Benign NTP",
                "East-west RDP",
            ],
            1,
            "What did the logs actually show?",
            "Correct. It is a strong delivery pattern, not a full IR conclusion. "
            "Common trap: writing \"confirmed APT\" from two lines. Remember: pattern ≠ verdict.",
        ),
    ],
    [
        _qz(
            "In the path DNS → HTTP, DNS usually contributes:",
            ["The HTTP status code", "The queried name and often the answer IP", "SMB share ACLs", "CVSS score"],
            1,
            "Correct. DNS contributes name/answer. Common trap: expecting status codes in DNS. "
            "Remember: status lives in HTTP.",
        ),
        _qz(
            "Strong Subject line for this path:",
            [
                "Suspicious",
                "WS-HR-03: DNS update.c0ntoso-finance.com then GET /u.exe 200",
                "Port 53",
                "User education only",
            ],
            1,
            "Correct. Host + DNS name + fetch outcome. Common trap: one-word subjects. "
            "Remember: timeline in the subject when you can.",
        ),
        _qz(
            "If HTTPS shows SNI=update.example.com but DNS answer IP is missing in your row:",
            [
                "You cannot mention the name",
                "You can still pivot on the SNI/query name match across the client timeline",
                "You must invent an IP",
                "It proves TCP/445",
            ],
            1,
            "Correct. Name match still works. Common trap: giving up without answer IP. "
            "Remember: SNI can bridge.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net/dns_before_download", "label": "Drill: DNS then HTTP", "why": "Prove the path on a snippet"},
    ],
)

# ── 9. Directions ─────────────────────────────────────────────────────────────
_add(
    "n09_directions", 9,
    "Egress, east-west, and ingress",
    16,
    "Label traffic as egress (out to internet), east-west (internal), or ingress (in from internet).",
    ["Egress", "East-west", "Ingress", "North-south", "Lateral movement"],
    [
        ("Direction words", """
            Egress means outbound traffic leaving the organization toward the internet
            (internal host → public IP). Analysts also say north-south for traffic that
            crosses the boundary between inside and outside.

            East-west traffic means internal host → internal host (workstation to workstation,
            or workstation to internal server). Lateral movement is attacker language for
            moving east-west after an initial foothold. Not every east-west flow is an attack;
            backups and admin tools also look east-west.

            Ingress means internet → internal host (outside trying to come in). Exposed RDP/SSH
            on a public IP is an ingress concern.
            """),
        ("Where you see this at work", """
            Same port, different direction, different ticket. TCP/3389 from internet to a
            server is ingress risk. TCP/3389 from WS-IT to WS-FINANCE is east-west remote
            desktop. TCP/4444 from a laptop to a rare internet IP is egress worth enriching.

            In analyst terms: direction is the frame around the port. You pick the frame
            before you tell the port story, or you escalate the wrong playbook.
            """),
        ("Technical specifics", """
            Quick labels:
              - private → public: egress
              - private → private: east-west
              - public → private: ingress
              - Confirm with asset inventory when 10.x is a guest or partner enclave

            SOC habits:
              - Odd egress ports: enrich destination + host process
              - East-west RDP/SMB: check whether the account and change window are expected
              - Ingress ALLOW on admin ports: high priority verify / escalate

            Worked example:
              A: 10.20.30.55 → 198.51.100.77 TCP/4444 → egress
              B: 10.20.30.12 → 10.20.30.77 TCP/3389 → east-west RDP
              C: 198.51.100.9 → 10.20.30.5 TCP/22 → ingress SSH

            How to answer:
              1. Classify private/public on each end.
              2. Name egress / east-west / ingress.
              3. Only then interpret port meaning in that context.

            Common trap: calling all TCP/443 "east-west" because both companies use HTTPS.
            If dst is on the internet, it is egress web, not east-west.

            Remember: direction first, then port story.

            Desk checklist you can reuse on every alert:
              1. Private or public on src?
              2. Private or public on dst?
              3. Pick egress / east-west / ingress from that pair.
              4. Only then interpret the port in that context.
              5. Write the direction word in the ticket Subject or What line.

            Why this order matters: the same TCP/22 means very different work if it is
            internet→jump host (ingress exposure) versus laptop→laptop (unexpected east-west
            shell) versus laptop→cloud admin IP (egress admin path). Port literacy without
            direction literacy produces wrong escalations.
            """),
    ],
    [
        _mc(
            "10.20.30.12 → 10.20.30.77 TCP/3389 is best labeled:",
            ["Egress to internet", "East-west (internal RDP)", "Ingress from Tor", "DNS only"],
            1,
            "Are both IPs private?",
            "Correct. Both private + 3389 = east-west RDP. Common trap: calling it egress. "
            "Remember: private→private = east-west.",
        ),
        _mc(
            "Internal host → rare internet IP on TCP/4444 is:",
            ["Ingress", "Egress worth enriching", "Always printers", "Proof of east-west SMB"],
            1,
            "Who is inside vs outside?",
            "Correct. Outbound to internet = egress. Common trap: labeling it ingress. "
            "Remember: inside→internet = egress.",
        ),
    ],
    [
        _qz(
            "Ingress means:",
            [
                "Internet (or outside) toward an internal host",
                "Only DNS queries",
                "Only east-west SMB",
                "A type of HTTP status",
            ],
            0,
            "Correct. Ingress is inbound. Common trap: swapping ingress and egress. "
            "Remember: ingress comes in.",
        ),
        _qz(
            "Lateral movement in this course refers to:",
            [
                "Attacker-style movement between internal hosts after foothold",
                "Buying a lateral Ethernet cable",
                "Only egress to Google",
                "HTTP 404 pages",
            ],
            0,
            "Correct. Lateral ≈ malicious east-west pattern. Common trap: calling every east-west "
            "flow lateral movement. Remember: east-west is the path; lateral is the hypothesis.",
        ),
        _qz(
            "North-south traffic crosses:",
            [
                "Only VLAN 1 to VLAN 1 with no gateway",
                "The inside/outside boundary (often egress or ingress)",
                "Only TCP/445",
                "Only UDP/123",
            ],
            1,
            "Correct. North-south crosses the perimeter. Common trap: using north-south for "
            "workstation-to-workstation. Remember: north-south = boundary.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net/rdp_lateral", "label": "Drill: RDP east-west", "why": "Practice direction labeling"},
        {"href": "/career/net/egress_4444", "label": "Drill: rare egress", "why": "Practice egress labeling"},
    ],
)

# ── 10. Firewall / flows ──────────────────────────────────────────────────────
_add(
    "n10_firewall_flows", 10,
    "Reading firewall and flow snippets",
    16,
    "Extract src, dst, protocol, dport, and action from a firewall or NetFlow-style line.",
    ["Firewall", "NetFlow", "ALLOW", "DENY", "dport"],
    [
        ("What these logs are", """
            A firewall decides whether a connection is allowed. Its log line is often your
            cleanest network evidence. NetFlow (and similar flow logs) summarize conversations:
            who talked to whom, on which ports, for how long, and how many bytes, sometimes
            without full packet payloads.

            Action ALLOW means the policy permitted the packet/session. DENY/DROP means it was
            blocked at that device. Neither word by itself finishes the investigation.
            """),
        ("Where you see this at work", """
            Boundry SIEM firewall rows look like:
              src=10.20.30.55 dst=198.51.100.77 proto=TCP sport=51884 dport=4444 action=ALLOW
            Your job is to read fields in a fixed order every time so you do not miss dport.

            In analyst terms: a firewall line is a structured sentence. If you skip a field,
            the next shift has to re-parse the raw event.
            """),
        ("Technical specifics", """
            Fixed read order:
              1. Timestamp
              2. src / dst (private vs public)
              3. proto
              4. dport (and sport only if relevant)
              5. action
              6. counts/bytes if present

            Ticket paste habit: keep field names. Do not translate into fluff.
            Good: src=10.20.30.55 dst=198.51.100.77 TCP dport=4444 ALLOW
            Weak: "firewall saw something weird"

            Worked example (count burst):
              src=10.20.40.9 dst=10.20.40.15,10.20.40.16,10.20.40.18
              proto=TCP dport=445 count=140 in 3m
            You extract: east-west SMB-shaped burst, one source, three peers, high count.
            Next questions: admin backup job? worm? scheduled scanner?

            How to answer:
              1. Underline dport before you interpret.
              2. Label direction.
              3. Quote action.
              4. Add volume if the log gives it.

            Common trap: reading ALLOW as "benign." ALLOW only means policy permitted it.
            Malware can ride allowed ports. DENY is not "user is safe on all paths."

            Remember: src, dst, proto, dport, action :  every time.

            Noise vs signal in firewall rows:
              - Repeated DENY from the internet to a closed port can be scan noise; still note
                if volume spikes or a new dst port opens later.
              - Single ALLOW on an odd high port from a user subnet is often more interesting
                than thousands of DENYs on TCP/23.
              - If sport and dport are both high and both ends are private, you may be looking
                at ephemeral client ports for an already-established session; look for the
                original service port in related rows.

            Boundry habit: paste the raw field line into What, then add one plain-English
            sentence. Never replace the fields with only adjectives. If a NetFlow row lacks
            action, still cite src, dst, proto, dport, and bytes/time so direction and
            volume survive the handoff.
            """),
    ],
    [
        _mc(
            "In src=10.20.30.55 dst=198.51.100.77 proto=TCP dport=4444 action=ALLOW, the service port to cite is:",
            ["10.20.30.55", "4444", "The VLAN tag", "ALLOW"],
            1,
            "Which field is dport?",
            "Correct. dport 4444 is the service port. Common trap: citing only ALLOW. "
            "Remember: dport first among ports.",
        ),
        _mc(
            "Firewall ALLOW means:",
            [
                "Confirmed safe business traffic forever",
                "This device's policy permitted the session/packet",
                "DNS failed",
                "The user completed MFA",
            ],
            1,
            "ALLOW is a policy result.",
            "Correct. ALLOW is permission, not a verdict of innocence. "
            "Common trap: ALLOW = close with no notes. Remember: policy ≠ benign.",
        ),
    ],
    [
        _qz(
            "NetFlow-style logs are most helpful because they:",
            [
                "Always include full HTTP bodies",
                "Summarize who talked to whom on which ports with volume/time",
                "Replace EDR process trees",
                "Prove phishing intent alone",
            ],
            1,
            "Correct. Flows summarize conversations. Common trap: expecting full URLs in every "
            "flow. Remember: flows = conversation metadata.",
        ),
        _qz(
            "Best first underline on a firewall line:",
            ["The analyst's mood", "dport (and proto)", "Only the color of the SIEM theme", "CVSS"],
            1,
            "Correct. Port/proto drive the service story. Common trap: reading action first and "
            "stopping. Remember: underline dport.",
        ),
        _qz(
            "140 hits in 3 minutes on TCP/445 east-west should appear in the ticket as:",
            [
                "Volume/count context with both ends",
                "Nothing, counts never matter",
                "Proof of HTTPS phishing",
                "Proof DNS is down",
            ],
            0,
            "Correct. Volume changes triage. Common trap: ignoring count fields. "
            "Remember: cite volume when present.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net/egress_4444", "label": "Drill: firewall rare port", "why": "Read a flow under pressure"},
        {"href": "/career/net/smb_east_west", "label": "Drill: SMB burst", "why": "Practice volume + ends"},
    ],
)

# ── 11. Proxy / web logs ──────────────────────────────────────────────────────
_add(
    "n11_proxy_web", 11,
    "Reading proxy and web logs",
    16,
    "Extract user, URL/SNI, status, and bytes from a proxy/web allow or deny line.",
    ["Proxy", "URL", "Bytes", "User", "ALLOW", "DENY"],
    [
        ("What a proxy log adds", """
            A proxy is a middle box that web clients send requests through. It often sees the
            user identity, full URL (for HTTP or decrypted HTTPS), or at least the host/SNI,
            plus status and bytes. That is richer than a firewall line that only has IPs and
            ports.

            You still define terms before you judge: user is who authenticated to the proxy,
            URL is what was requested, bytes is how much came back, action is allow or deny
            at the proxy.
            """),
        ("Where you see this at work", """
            Email → user clicks → proxy ALLOW 200 on a lookalike domain. Your note should
            read like a browser story, not only "TCP/443."

            In analyst terms: the proxy answers who clicked and what name or URL they hit.
            Pair that with firewall direction when you need the port story too.
            """),
        ("Technical specifics", """
            Read order for proxy lines:
              1. user
              2. method + URL or host
              3. status
              4. bytes
              5. action
              6. src IP / device if present

            Compare to firewall:
              - Firewall: strong on direction + port
              - Proxy: strong on URL/user/status
              - Best tickets use both when available

            Worked example:
              user=ap.clerk@clientcorp.example method=GET
              url=https://c0ntoso-finance.com/wire-approve
              dport=443 http_status=200 action=ALLOW
            Story: identified user fetched wire-approve, 200, allowed. Next: was it a phish
            campaign URL? Any file write on endpoint?

            How to answer:
              1. Quote user and URL.
              2. Translate status.
              3. Note allow/deny.
              4. Pivot to DNS/firewall for the same minute if needed.

            Common trap: ignoring bytes. A 200 with 12 bytes of body is different from a 200
            with 20MB. Another trap: thinking DENY means the user never saw a lure elsewhere.

            Remember: proxy gives people and URLs; firewall gives ports and direction.

            When HTTPS is not decrypted, you still often get:
              - SNI / host name
              - destination IP and port
              - bytes transferred
              - allow or deny
            That is enough to pivot to DNS and to ask EDR what process owned the socket.
            Do not stop the case because the full URL path is missing.

            Ticket contrast example:
              Weak: "User hit 443."
              Strong: "ap.clerk GET host c0ntoso-finance.com status 200 bytes=482112 ALLOW;
              firewall shows same dst IP egress TCP/443."

            If the proxy user field is blank, cite the source IP or device name and say
            "user unknown at proxy." Do not invent a mailbox from a hostname guess.
            """),
    ],
    [
        _mc(
            "Compared with a bare firewall IP:port line, a proxy log is often better for:",
            [
                "Seeing user + URL/status",
                "Seeing cable length",
                "Seeing OSPF metrics",
                "Seeing badge door swipes",
            ],
            0,
            "What fields does a web proxy usually add?",
            "Correct. User/URL/status are proxy strengths. Common trap: using only dport=443. "
            "Remember: proxy = people and URLs.",
        ),
        _mc(
            "Large bytes with HTTP 200 on a rare domain suggests you should:",
            [
                "Ignore bytes forever",
                "Note a likely download/content transfer and continue host/intel checks",
                "Close as NTP",
                "Rewrite the status as 404",
            ],
            1,
            "What do bytes add to a 200?",
            "Correct. Bytes hint at transfer size. Common trap: status without size. "
            "Remember: 200 + bytes = how much came back.",
        ),
    ],
    [
        _qz(
            "Best fields to copy from a proxy allow on a phish URL:",
            [
                "Only dport",
                "user, URL, status, bytes, action",
                "Only the theme color",
                "Only sport",
            ],
            1,
            "Correct. Those five carry the web story. Common trap: port-only paste. "
            "Remember: user + URL + status.",
        ),
        _qz(
            "If proxy DENY and firewall ALLOW exist for similar destinations, you should:",
            [
                "Pick one at random and delete the other from the ticket",
                "Cite both hops; policies can differ by path",
                "Assume the user is a domain admin",
                "Convert both to UDP/53",
            ],
            1,
            "Correct. Different devices can disagree. Common trap: trusting only one log. "
            "Remember: cite each hop.",
        ),
        _qz(
            "SNI on an HTTPS proxy log is valuable because:",
            [
                "It often exposes the requested server name even when the path is encrypted",
                "It proves SMB",
                "It replaces MFA",
                "It is an HTTP 404",
            ],
            0,
            "Correct. SNI carries the name. Common trap: \"HTTPS means zero visibility.\" "
            "Remember: SNI/host still helps.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net/http_phish_200", "label": "Drill: proxy HTTP 200", "why": "Cite URL + status"},
    ],
)

# ── 12. Ticket story ──────────────────────────────────────────────────────────
_add(
    "n12_ticket_story", 12,
    "Combining artifacts into a ticket story",
    16,
    "Build Subject / What / Why / Next from mixed DNS + firewall + proxy clues without inventing malware.",
    ["Subject", "What", "Why", "Next", "Disposition"],
    [
        ("Ticket hygiene for network cases", """
            Disposition means your outcome label: escalate, monitor/enrich, or close as
            benign/expected with reason. Boundry Portfolio style fields map cleanly:
              - Subject: one line with host + sharp clue
              - What: facts from logs (no adjectives first)
              - Why: why those facts matter (pattern language)
              - Next: who does what
              - MITRE later if you have a technique; do not force it from a port alone
            """),
        ("Where you see this at work", """
            You have DNS, a firewall ALLOW, and a proxy 200. Writing three separate mini-notes
            confuses handoff. One story with timestamps wins interviews and night shifts.

            In analyst terms: the ticket is the product. Logs are ingredients. Mix them once
            into Subject / What / Why / Next so nobody re-cooks the case from scratch.
            """),
        ("Technical specifics", """
            Assembly order:
              1. Identity: host/user
              2. Timeline bullets (DNS → firewall/proxy)
              3. Direction + port/service
              4. Status/bytes/action
              5. Decision + next owner

            Template:
              Subject: <host>: <domain or dport clue> <status/action>
              What: <timestamped facts>
              Why: <pattern; not novel-length threat intel>
              Next: <enrich X / escalate to Y / close because Z>

            Worked example:
              Subject: WS-HR-03: update.c0ntoso-finance.com → /u.exe 200
              What: 14:01:02 DNS A to 203.0.113.88; 14:01:04 GET /u.exe 200 bytes=482112;
                    firewall ALLOW TCP/80 to same IP.
              Why: lookalike domain + executable fetch pattern.
              Next: EDR file/process on WS-HR-03; intel on domain/IP; escalate if payload runs.

            How to answer under time pressure:
              1. Paste artifacts first.
              2. Add one why sentence.
              3. Add one next sentence.
              4. Stop. Do not novelize.

            Common trap: inventing malware family names from a port. Another trap: burying the
            destination port in a paragraph of fear language.

            Remember: facts, pattern, next :  in that order.

            Quality bar before you hit Submit:
              - Could a teammate continue without pinging you?
              - Did you paste at least one raw artifact line?
              - Did you name direction and the main port or DNS/HTTP clue?
              - Is Next owned (you enrich, Tier-2 contains, host team confirms backup)?

            If any answer is no, spend thirty more seconds. That is cheaper than a bad handoff
            at 02:00. Boundry Portfolio export later rewards the same hygiene, so practice it
            here on every network case. When you are unsure of MITRE, leave the technique blank
            and keep the network nouns strong rather than forcing a wrong tag.
            """),
    ],
    [
        _mc(
            "Best opening for the What section:",
            [
                "This is definitely APT29",
                "Timestamped DNS and HTTP facts with IPs/ports/status",
                "I have a bad feeling",
                "Closing, noise",
            ],
            1,
            "What belongs before opinions?",
            "Correct. Facts first. Common trap: leading with attribution. "
            "Remember: What = evidence.",
        ),
        _mc(
            "Why section should mostly use which tone?",
            [
                "Pattern language tied to the artifacts",
                "Guaranteed court-ready attribution",
                "Jokes only",
                "Empty",
            ],
            0,
            "How do you avoid overclaiming?",
            "Correct. Say the pattern the logs support. Common trap: naming a nation-state "
            "from one fetch. Remember: pattern, not novel.",
        ),
    ],
    [
        _qz(
            "A complete network ticket mini-story needs at least:",
            [
                "Subject/What/Why/Next grounded in artifacts",
                "Only a GIF",
                "Only the word lateral",
                "Only CVSS",
            ],
            0,
            "Correct. Those four fields hand off cleanly. Common trap: What without Next. "
            "Remember: always give Next.",
        ),
        _qz(
            "Inventing a malware family from TCP/4444 alone is:",
            [
                "Required",
                "A common trap; enrich and use host evidence first",
                "How DNS works",
                "How HTTP 302 works",
            ],
            1,
            "Correct. Port ≠ family name. Common trap: dramatic labels without EDR/intel. "
            "Remember: do not invent malware.",
        ),
        _qz(
            "Disposition means:",
            [
                "Your outcome choice (escalate / enrich / close with reason)",
                "The destination port only",
                "The TLS version only",
                "A type of VLAN",
            ],
            0,
            "Correct. Disposition is the outcome. Common trap: leaving disposition blank. "
            "Remember: every ticket ends with a decision.",
        ),
    ],
)

# ── 13. SOC decisions ─────────────────────────────────────────────────────────
_add(
    "n13_soc_decisions", 13,
    "Enrich, escalate, or close",
    16,
    "Pick the next SOC move from network evidence alone (enrich, escalate, document-and-close).",
    ["Enrich", "Escalate", "Close", "False positive", "Expected admin"],
    [
        ("Three doors", """
            After you can read the snippet, you choose a door:

            Enrich means gather more context before a big move: domain/IP reputation, EDR
            process tree, user reach-out per playbook, related alerts in the last hour.

            Escalate means hand to Tier-2 / IR / host team with a crisp package because impact
            or confidence is high enough that waiting is worse.

            Close (document-and-close) means the activity is explained as expected or benign
            enough for policy, and your note would let an auditor see why. False positive means
            the alert fired but the activity is not malicious. Expected admin means real admin
            work that matched a change window or known tool.
            """),
        ("Where you see this at work", """
            Rare egress 4444 with no process yet → enrich. Confirmed malware process + rare
            egress → escalate. Nightly backup SMB burst with ticket CHG-123 → close as expected
            admin with the change number cited.

            In analyst terms: the three doors are about confidence and impact, not about how
            exciting the alert title sounds. Network facts decide which door you open.
            """),
        ("Technical specifics", """
            Decision cues (network-centered):
              Enrich when: uncommon port or rare domain, but missing host/process or intel
              Escalate when: ingress admin port ALLOW unexpected, clear malware fetch + execution,
                or active east-west RDP/SMB paired with hostile process
              Close when: known backup/scanner ranges, change-controlled admin, or deny with no
                bypass evidence and playbook says monitor-only

            Package for escalate (minimum):
              - Subject + timeline
              - src/dst/dport/proto/direction
              - DNS/URL/status if any
              - What you already checked
              - What you want Tier-2 to do

            Worked example A (enrich): WS → internet TCP/4444 ALLOW, EDR offline.
              Decision: enrich (intel on dst, bring host online in EDR, recheck in 15m).

            Worked example B (escalate): DNS lookalike + GET u.exe 200 + EDR shows powershell
              from the dropped file. Decision: escalate with containment request per playbook.

            Worked example C (close): TCP/445 burst from BACKUP-01 to file servers during
              documented window. Decision: close expected admin; cite CHG.

            How to answer:
              1. List facts.
              2. Ask what is missing.
              3. If missing critical host/intel and impact unclear → enrich.
              4. If hostile process or exposed admin ingress → escalate.
              5. If explained by change/tooling → close with citation.

            Common trap: closing rare egress because "probably a developer" with no name, no
            change ticket, and no process. Another trap: escalating every 443 to Cloudflare.

            Remember: enrich when unsure, escalate when impact is clear, close when explained.

            When two doors feel equally right, write the safer interim move: enrich with a
            time box ("recheck in 15m / after EDR check-in") rather than a silent close.
            """),
    ],
    [
        _mc(
            "Nightly SMB from BACKUP-01 to file servers with CHG-123 is best handled as:",
            [
                "Escalate as nation-state",
                "Document-and-close as expected admin with the change cited",
                "Ignore with no ticket text",
                "Rewrite as DNS C2",
            ],
            1,
            "Do you have an explanation that matches the artifacts?",
            "Correct. Expected admin closes with citation. Common trap: escalating backups "
            "forever. Remember: cite the change.",
        ),
        _mc(
            "Rare egress TCP/4444 and EDR offline :  best first door:",
            ["Close as benign with no notes", "Enrich (intel + restore telemetry)", "Reimage the whole floor", "Disable DNS company-wide"],
            1,
            "What is missing?",
            "Correct. Enrich when process evidence is missing. Common trap: instant close. "
            "Remember: missing host telemetry → enrich.",
        ),
    ],
    [
        _qz(
            "Escalate is most appropriate when:",
            [
                "You have a clear hostile process plus bad network fetch/ingress admin exposure",
                "You only saw TCP/443 to a major CDN with no other signal",
                "You have not opened the log yet",
                "The flashcard front is TCP/22",
            ],
            0,
            "Correct. High confidence + impact → escalate. Common trap: escalating generic web. "
            "Remember: escalate with a package.",
        ),
        _qz(
            "False positive means:",
            [
                "The alert fired but activity is not malicious / not what the rule feared",
                "The firewall melted",
                "DNS cannot work",
                "Always equal to ransomware",
            ],
            0,
            "Correct. FP = alert without true badness. Common trap: using FP to mean \"I am tired.\" "
            "Remember: FP needs a reason in the note.",
        ),
        _qz(
            "Minimum escalate package includes:",
            [
                "Timeline, network nouns, what you checked, ask for Tier-2",
                "Only the word urgent",
                "Only a meme",
                "Only the quiz score",
            ],
            0,
            "Correct. Give Tier-2 a runnable package. Common trap: escalate with no artifacts. "
            "Remember: package beats panic.",
        ),
    ],
)

# ── 14. Capstone ──────────────────────────────────────────────────────────────
_add(
    "n14_capstone_signals", 14,
    "Capstone: name the signal",
    18,
    "Apply the full path on prove-it signal drills (ports, DNS/HTTP, direction, checklist).",
    ["Signal", "Checklist", "Prove-it", "Direction"],
    [
        ("Bring the whole course to one snippet", """
            A signal here means the primary network story type you select in Boundry drills:
            rare egress port, DNS then HTTP, RDP 3389, SMB 445, HTTP web with status, or SSH 22.
            Direction is egress, east-west, or ingress. The checklist asks whether the snippet
            truly shows a destination port, a DNS-primary story, an east-west pattern, or an
            HTTP status worth citing.

            This lesson is the bridge into the hub Prove-it drills. You already practiced the
            ideas. Now you grade yourself the way the lab grades you.
            """),
        ("Where you see this at work", """
            Real queues mix signals. Your speed comes from a fixed scan: ports → names →
            status → direction → decision. The drills force that scan under a scoring rubric.

            In analyst terms: Prove-it is not trivia. It is the same scan you run when a
            Quick Shift dumps three network alerts in two minutes.
            """),
        ("Technical specifics :  drill playbook", """
            For every snippet:
              1. Read dport/proto or DNS/HTTP fields first (do not skim to the answer buttons)
              2. Pick the signal that matches the primary story (not a side detail)
              3. Label direction from IP private/public pattern
              4. Checklist: mark true only if the snippet actually shows that evidence
              5. Pass is 70%+ on Boundry grading (signal + direction + checklist)

            Signal reminders:
              - rare_egress_port: uncommon outbound dport to internet
              - dns_then_http: name lookup then fetch
              - rdp_3389 / smb_445 / ssh_22: service-shaped east-west or admin paths
              - http_web: URL/status web story on 80/443

            Worked example (mental dry run):
              src=10.20.30.12 dst=10.20.30.77 TCP/3389 ALLOW, both internal hostnames
              Signal: RDP 3389. Direction: east-west. Checklist: cites_dst_port true;
              dns_query_primary false; east_west_pattern true; http_status_cited false.

            How to answer in the lab:
              1. Open a drill with a seed (variants change hosts/IPs, not the lesson).
              2. Grade once. Read the teach-back.
              3. Rotate to the next drill.
              4. Return to weak lessons if you miss the same idea twice.

            Warm-up before a graded run: say the shortlist ports, then label one private and
            one public IP, then name one 200 versus one 302. That thirty-second reset cuts
            careless misses on checklist items.

            Common trap: picking DNS signal because port 53 appears in a side note while the
            snippet's main story is RDP. Primary story wins. Another trap: marking HTTP status
            cited when no status code exists in the text.

            Remember: primary signal + direction + honest checklist = pass.
            """),
    ],
    [
        _mc(
            "Both internal hosts, TCP/3389 ALLOW. Best signal + direction pair:",
            [
                "http_web + egress",
                "rdp_3389 + east_west",
                "dns_then_http + ingress",
                "rare_egress_port + ingress",
            ],
            1,
            "Port and IP classes decide this.",
            "Correct. RDP east-west. Common trap: calling workstation RDP \"egress.\" "
            "Remember: 3389 + private→private = east-west RDP.",
        ),
        _mc(
            "Checklist item \"http_status_cited\" should be true only when:",
            [
                "You wish there were a status",
                "The snippet actually includes a status code such as 200",
                "The port is 445",
                "The direction is east-west",
            ],
            1,
            "Does the text contain a status?",
            "Correct. Checklist honesty matters. Common trap: marking true from memory of "
            "another drill. Remember: only what the snippet shows.",
        ),
    ],
    [
        _qz(
            "Primary signal for DNS name then GET u.exe 200 is:",
            ["smb_445", "dns_then_http", "rdp_3389", "ssh_22"],
            1,
            "Correct. DNS-then-HTTP is the primary story. Common trap: picking http_web only and "
            "dropping DNS. Remember: when DNS leads, name that signal.",
        ),
        _qz(
            "Rare internet dport 4444 from a 10.x host is usually:",
            ["east_west", "egress_internet", "ingress_internet", "Not a direction"],
            1,
            "Correct. Internal to internet = egress. Common trap: ingress. "
            "Remember: inside→internet = egress.",
        ),
        _qz(
            "Boundry net drill pass threshold is:",
            ["10%", "70%", "100% only", "No scoring"],
            1,
            "Correct. Pass at 70%+. Common trap: stopping at a failing score without reading "
            "teach-back. Remember: learn from the grade, then rotate.",
        ),
        _qz(
            "After this lesson you should:",
            [
                "Run hub signal drills and keep using Show me → Help me → Prove it on weak spots",
                "Delete the flashcards",
                "Skip citing ports forever",
                "Start a CCNA rack lab instead of tickets",
            ],
            0,
            "Correct. Drills are the capstone Prove-it. Common trap: reading only, never drilling. "
            "Remember: prove it on snippets.",
        ),
    ],
    job_ctas=[
        {"href": "/career/net#drills", "label": "All signal drills", "why": "Capstone Prove-it"},
        {"href": "/career/net/dns_before_download", "label": "DNS→HTTP drill", "why": "Path practice"},
        {"href": "/career/net/rdp_lateral", "label": "RDP east-west drill", "why": "Direction practice"},
    ],
)

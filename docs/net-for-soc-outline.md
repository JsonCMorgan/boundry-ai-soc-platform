# Net-for-SOC  -  Lesson Outline

Analyst networking course (SOC-focused, not CCNA). Teach what Tier-1 cites in
tickets: ports, DNS, HTTP status, traffic direction, and how to turn a snippet
into a disposition. Original Boundry content only.

**Spine:** Show me → Help me → Prove it (≥70%). Existing flashcards and signal
drills stay on the hub as early practice and parallel Prove-it.

| # | ID | Title | One-line objective |
|---|-----|-------|--------------------|
| 1 | `n01_why_net` | Why SOC analysts need networking | Explain why a ticket that only says "suspicious traffic" fails, and what network facts L1 must cite. |
| 2 | `n02_hosts_ips` | Hosts, IPs, and private vs public | Read source/destination IPs and tell whether they look internal (private) or internet-facing (public). |
| 3 | `n03_tcp_udp` | TCP, UDP, and connections | Distinguish TCP vs UDP for ticket language, and say what a destination port names. |
| 4 | `n04_ports_matter` | Ports that matter on tickets | Cite the SOC shortlist (22, 3389, 445, 80/443, 53, 25/587) with the service each usually means. |
| 5 | `n05_port_flashcards` | Port flashcards deep dive | Drill the same port facts as flashcards until you can name service + why L1 cares. |
| 6 | `n06_dns_basics` | DNS: names before downloads | Explain what a DNS query proves, and why the query name often matters more than a raw IP alone. |
| 7 | `n07_http_status` | HTTP/HTTPS and status codes | Read method, URL/host, and status (200 vs 302 vs 403/404) as evidence of what the client got. |
| 8 | `n08_dns_http_path` | Following the DNS → HTTP path | Chain a DNS lookup to a later HTTP(S) fetch into one timeline story for the ticket. |
| 9 | `n09_directions` | Egress, east-west, and ingress | Label traffic as egress (out to internet), east-west (internal), or ingress (in from internet). |
| 10 | `n10_firewall_flows` | Reading firewall and flow snippets | Extract src, dst, protocol, dport, and action from a firewall or NetFlow-style line. |
| 11 | `n11_proxy_web` | Reading proxy and web logs | Extract user, URL/SNI, status, and bytes from a proxy/web allow or deny line. |
| 12 | `n12_ticket_story` | Combining artifacts into a ticket story | Build Subject / What / Why / Next from mixed DNS + firewall + proxy clues without inventing malware. |
| 13 | `n13_soc_decisions` | Enrich, escalate, or close | Pick the next SOC move from network evidence alone (enrich, escalate, document-and-close). |
| 14 | `n14_capstone_signals` | Capstone: name the signal | Apply the full path on prove-it signal drills (ports, DNS/HTTP, direction, checklist). |

## Phase map

1. **Foundations**  -  lessons 1-3  
2. **Ports**  -  lessons 4-5 (+ hub flashcards)  
3. **DNS / HTTP path**  -  lessons 6-8  
4. **Directions**  -  lesson 9  
5. **Reading artifacts**  -  lessons 10-12  
6. **SOC decisions**  -  lessons 13-14 (+ hub drills)

## Unlock (hybrid)

- Lesson 1 is always recommended.  
- Lesson N+1 is **recommended** after Prove-it pass (≥70%) on lesson N.  
- Soft unlock: you can still open any lesson; the hub shows a nudge toward the Continue lesson.  
- Signal drills remain available in parallel as hands-on Prove-it.

## Out of scope (not CCNA)

Subnet math drills, OSPF/BGP, VLAN design, switch CLI, cable standards, full Wireshark certification depth.

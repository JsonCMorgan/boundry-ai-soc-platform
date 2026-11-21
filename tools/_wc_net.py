"""Count Show-me word totals for Net-for-SOC lessons."""
import net_lessons

for lesson in net_lessons.LESSONS:
    text = " ".join(s["body"] for s in lesson["sections"])
    words = len(text.split())
    heads = [s["heading"] for s in lesson["sections"]]
    flag = "OK" if words >= 400 else "THIN"
    print(f"{flag:4} {lesson['id']:28} {words:4}  {heads}")

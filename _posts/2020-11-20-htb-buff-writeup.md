---
title: "How-to: Conquer the OSCP"
author: jwashek
date: 2020-02-05 20:25:00 +0800
categories: [How-To's, Cert Conquering]
tags: [oscp, tryharder, enumerate]
image: /assets/img/post/oscp/oscp.png
---

> *The [OSCP](https://www.offensive-security.com/pwk-oscp/) is a 100% hands-on certification where the student takes on the challenge to perform a penetration test against a network to simulate a real-world penetration test. The exam is broken down into 2 phases. The first phase, the student has 24 hours to complete the penetration test of several machines where they need to obtain at least 70 points in order to pass. The second phase, the student has another 24 hours to write a professional penetration testing report.*

## Quick Description
This post is going to serve as my experience with the OSCP -- both with the labs and exam. I'm attempting to be as detailed and thorough in my descriptions, experience, and tooling as I can to help anyone and everyone who is thinking of taking the exam.

> <u><b>Note:</b></u> Out of respect to Offensive Security, I cannot dive deep into the lab or exam machines, so do not expect to see specific vulnerabilities called out or any how-to's relevant to these machines. Obvious? Maybe. Needed to be said? ...also maybe.

## The Labs
Ask just about any OSCP-holder about the exam and you're more than likely to receive the same answer:  

> *"It's not about the certification, it's about the journey."*

After taking the exam, I can say that I 100% agree. The labs served as the main area of learning. Offensive Security put together a fantastic course with highly detailed videos and PDF content; however, the bulk of the learning will absolutely be "by doing" in a hands-on approach with hacking in the labs. The lab machines consisted of both Linux and Windows hosts, which gives the student a well-rounded approach in hacking different technologies.

### My Experience
Just after I received my VPN connectivity pack, I decided to go against what was recommended (i.e., read the PDF and do the course work first) and decided to go straight to the labs. Having done this, I'd recommend against doing what I did since there were certain machines that needed to be hacked in a certain order (vague, I know). Without giving too much away, there is more information contained within the PDF for tackling this.

#### My Timeline
All of that being said, I started my course in late August 2020 and started hacking in the labs the very same night. I grabbed a random machine from the list, not paying attention to what the course materials or PDF had mentioned (way to go Justin), and go figure it was one of the "Big 4" machines -- **Pain** to be exact. This was a huge **Pain** (pun intended) and hit to my pride as I, at that point, had rooted ~25 [Hack The Box](https://www.hackthebox.eu/) machines and ~15 [TryHackMe](https://tryhackme.com/) machines. At this stage, I hit a wall and just decided to take as detailed of notes that I could and move onto another machine. The next machine went much more smooth and I ended up rooting it in under 2 hours. This was a big boost in confidence and I decided to keep doing the pick-a-machine-any-machine approach.

After about 25 days of lab access, I had rooted over 30 machines, which was at least 1 machine a day. Having a little baby at home, I only had about 2-3 hours to really focus on hacking. After the little one went to bed, I switched "Dad Mode" into straight up "Hacker Mode" and went ham against the lab machines for the short amount of time that I had. This served to be an extremely serendipitous event, as I'll get to later in the post.

> Now that I earned the OSCP, I can use pretentious words like "serendipitous" in a blog post. Clearly I'm joking, people, it's apparently the best word for the occasion...

### Lab Relevance to the Exam
If I were to answer honestly, I'd say that the labs helped my mindset going into the exam. My "mindset" referring to how I actually tackle a machine; my methodology. Are the labs relevant to what you'll see in the exam? Yes and no.

- **Yes** -- because you're going to perform the same methodology to find and exploit vulnerabilities (i.e., port/service discovery, enumeration, exploitation, post-exploitation).

- **No** -- because you're not going to see a one-for-one exact match between any of the labs and the exam machines. Kind of to be expected, though, right?

So, what is more relevant to the exam? Hack The Box, believe it or not, is the most relevance you'll get to the exam without having the same vulnerabilities. Overall, I felt as though the OSCP lab machines were a little on the easier side, whereas the Hack The Box machines had a lot more trolls, red-herrings, and unique initial footholds and privilege escalation paths. More specifically, if you don't feel like going through all of TJ Null's [OSCP-like machines](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159), your go-to should be watching [ippsec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) videos. Every video located in his [OSCP prep](https://www.youtube.com/watch?v=2DqdPcbYcy8&list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf) playlist. All of them. Definitely do not skip watching any walkthroughs since he *always* provides very valuable insight and usually provides different methods to root the machines.

## The Exam
### My Experience
Let me first preface by saying that I am one of those dudes with some horrible luck. That tragedy struck like Chris Brown the second I started the exam. First, I had a little connectivity issue with the VPN which just required me to scrap my connectivity pack, re-download, and try again. Easy fix (~20 min wasted).

During the buffer overflow, however, is where my problems came crashing through the door like a shark at a surfer convention. I quickly noticed that **nothing** was working. Python and Ruby -- along with any pre-installed tool written in Python or Ruby -- were just... not working. I had dependency errors that I didn't have the days leading up to the exam; I had modules and gems that mysteriously disappeared into the ether; and I could swear that I heard my VM laughing at me when trying to fix the issues.

For some odd reason the night before my exam, I had a soul-altering revelation:

> "Justin..." I said, "how about you take a snapshot in case the hell hounds are released against your whole entire existence before the exam?"

Luckily, I was able to restore from a previous snapshot and like some sort of witchcraft, everything worked like nothing happened. Given the troubleshooting before I restored my snapshot (i.e., attempting to fix the dependency errors, installing Python modules and Ruby gems, etc.) I had wasted about 1 hour.

After the kinks were all taken out of the wrinkled garden hose that is my life, I was able to continue with the exam -- much like probably 99.9887% of exam takers that don't run into a Thanksgiving dinner of issues like I did.

### My Timeline
I started my exam at **6:00pm** on a Friday (January 29th, 2021 to be exact). As alluded to above, this was my "serendipitous" moment. It benefited me because I really only had a few hours to practice once my little one was either napping or sleeping. I was so used to forcing myself to "git gud" and hack a machine in the short amount of time that I had, that I was already accustomed to hacking at this time of night anyways. Therefore, it was actually beneficial to me starting my exam at **6:00pm** -- though your mileage may vary. In addition, this time of day generally gave me enough time to get 2 machines before I went to bed (assuming ~2 hours per machine) -- which was my hope for the exam as well. Below is a more detailed breakout of the timeline:

**Friday, January 29th 2021**
- **6:00pm** -- Start of exam and started my recon.
- **7:20pm** -- Okay, this was *really* the start of the exam after all the issues were sorted out. I also had to start all over with the recon after restoring my VM snapshot. What a time to be alive.
- **7:50pm** -- Rooted the Buffer Overflow machine (25 points down, 45 points to go)
- **8:00pm** -- Took a small break and went for the 10 point machine. This is where the Imposter Syndrome set in. And very, *very* hard.
- **10:00pm** -- Yes, two hours later on the EASY machine... and I still didn't get anywhere. Justin, what are you doing, bro?!
- **10:30pm** -- Switched to a different machine. Fully rooted a 20 point machine (45 points down, 25 points to go).
- **10:30pm - 11:30pm** -- Went back to the 10 point machine. Guess who STILL couldn't figure it out? Yep, yours truly.
- **11:45pm** -- Went to sleep, but that's both a lie and an overstatement. There wasn't much "sleeping" going on as it mainly consisted of me laying there angry with myself over the 10 point machine. I busted out the "Critical Names to Call Yourself When You're Really Angry For Not Figuring Something Out and Laying in Bed Wide-Awake" book. Even though I had plenty of time, I was being extremely critical on myself since the "easy" machine was supposed to be, well, easy. In addition to self-inflicted verbal wounds, I started to have an existential crisis:
  - Why couldn't I figure this out?
  - What am I doing with my life?
  - Is this even what I'm supposed to be doing?
  - Is cereal technically soup?
  - Just who killed JFK?!?!

**Saturday, January 30th 2021**
- **6:00am** -- Woke up. Heh, "woke up". I wish I actually slept that night.
- **6:30am** -- I decided to take a breather, clear my head, and attack the 25 point machine.
- **7:00am - 1:00pm** -- I found a good vulnerability, but otherwise got nowhere with a low-privilege shell on the hard machine. Existential Crisis Part Deux sets in. This is where I take my <u>first</u> (yes, first) real break, 0/10 would not recommend. Frequent breaks are a *must*!
- **1:30pm** -- While on break, the clouds opened and a bright white light appeared with my beautiful, angelic inner-voice saying, "Justin, you know you found this vulnerability, why not try to get a shell by chaining the `<REDACTED>` vulnerability on port `<REDACTED>` to try and enumerate the `<REDACTED>` service on port `<REDACTED>` using the `<REDACTED>` method?"
  - "Oooh", thought I, "will that even work?"
- **2:00pm** -- Why, yes, yes it did work! "Justin, forget all of those terrible things I said about you..." I fully rooted the 25 point machine (70 points down, 0 points to go) with a super awesome vulnerability chain that I had never done before.
- **2:30pm** -- I fired up Metasploit (before you ask: Yes. I *100%* used Metasploit on the 10 point machine. I wasn't about to go out in defeat with the "easy" machine) and rooted the "TeN PoInT mAChiNe" (80 points down, -10 points to go).
- **2:30pm - 3:30pm** -- I took a much needed mental break and decided against going for the remaining 20 points. The reasons were twofold: (1) I needed every last minute to write as detailed of a report as I could; and (2) I knew this machine was heavy on enumeration and I needed the remaining ~2 hours to get as many screenshots as I could and make sure that I submitted all my proofs in the Exam Panel.

## The Report
### My Experience
I can honestly say that I underestimated the difficulty of writing a report after the 24 hour penetration test. I was exhausted both mentally and physically. My lack of sleep really started to hit me hard here. I knew that I had a lot of time to write the report, but I also knew that time was very valuable and quickly dwindling away. All of that being said, it's just another one of those "Try Harder" moments that Offensive Security loves to sing about. Literally.

<iframe width="560" height="315" src="https://www.youtube.com/embed/t-bgRQfeW64" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>

### My Timeline
Since I ended my exam slightly early, I had ~2.5 extra hours to focus on the report -- something that I later found out was much needed in my personal experience.

I started the report at about **4:00pm** on Saturday, January 30th or about 22 hours after my initial exam start time. I used up just about every last minute of this time and finished the report at **3:45pm** on Sunday, January 31st. I had 2 hours and 15 minutes to zip up my report and upload it to Offensive Security. I re-read my report (by "re-read", I actually meant to say that I "re-read it 1,000  more times, made minor adjustments, changed it back to how it was before, played with the formatting, spellchecked, then did one final proof-read"). After all was said and done with the report, I was able to have everything finalized and sent to Offensive Security for review by **4:30pm** on Sunday, January 31st.

## Tips and Tricks
### Tips
- **Take frequent breaks.** This one might be obvious, but it's easy to gloss over when you're deep in thought and you just want to make that major breakthrough on a machine. In my case, I credit a large portion of why I was able to root the 25 point machine because of that break. Conversely, I credit a large portion of why I struggled where I did to not taking breaks when I got frustrated or when I was mentally drained and needed to clear my thoughts. It's important... just do it.
- **Relax.** Is the OSCP tough? Yes, absolutely. Is it impossible? Not at all! If I can do it, anyone can do it. Just remember: Offensive Security didn't make the exam impossible; there's at least one way into every machine.
- **Be efficient.** The assessment portion is 24 hours. Seems like a lot of time, right? It flies by *very* quickly. For this reason, you <u>must</u> be efficient in your reconnaissance and enumeration. A good way to do this is to have recon going on in the background. Did you find SQLi, command injection, or a file upload vulnerability that you want to check manually? Make sure while you're manually testing that you have deeper enumeration running. Maybe this is another directory brute-forcing scan that includes other extensions (.php, .asp, .aspx, .html, .txt, .bak, .tar, .cgi, etc); maybe this is a Nikto scan on another service; maybe this is a Hydra brute-forcer against a login page; the point is to have something going on while you're doing your manual assessment. Not only will this save time, but it may just give you that extra push into getting a shell.
- **Enumerate, enumerate, enumerate.** I'd be willing to bet that you've heard "enumerate" at least 1,000 times while going through the OSCP course. One thing that people don't say is what this actually means. Enumeration (I guess you've heard it 1,001 times now) is the process of finding attack vectors on a given target. That being said, enumeration has no exact science, but it is an art-form that is learned over time. One big tip that I can give is to replace the word "enumerate" with "Google." For example, if you see a service that you want to "enumerate", Google it. Is there a specific version running on a service that you found? Google it. 
- **Write detailed notes.** The idea here is to write the notes detailed enough where, if you didn't screenshot something that you knew you should have, you can consult your notes, grab what you need, and be on your way. Is this an oddly specific tip? Yes, I totally forgot a screenshot in my report, but I had more than enough notes to build that section in a still really detailed manner.
- **Listen to music.** I will be the first to admit of my nerdy-ness in what type of music helps me to concentrate. This includes game OSTs like from Silent Hill ([Silent Chill](https://www.youtube.com/watch?v=vteCosE9qnM)), [Skyrim](https://www.youtube.com/watch?v=aQeIYVM3YBM), and [Oblivion](https://www.youtube.com/watch?v=SpqSdORmCX4). My specific playlist I used for the OSCP consisted of all of the above and one my favorite YouTubers, [Marc Rebillet](https://www.youtube.com/channel/UCXgxNzAgZ1GExhTW4X1mUrg). Hey, whatever works, right?
- **Get comfortable with buffer overflows.** Another seemingly obvious "tip", but the tip here is the specific resource I wanted to mention. If you were like me and are very weak in Buffer Overflows, please do yourself a favor and follow these two steps:
  - Step 1:  Go through The Cyber Mentor's buffer overflow [playlist](https://www.youtube.com/watch?v=qSnPayW6F7U&list=PLLKT__MCUeix3O0DPbmuaRuR_4Hxo4m3G).
  - Step 2:  Do this [Buffer Overflow prep](https://tryhackme.com/room/bufferoverflowprep) room on TryHackMe. Without giving anything away, just trust me when I say this is all you'll need for your OSCP buffer overflow prep. Additionally, Tib3rius does a phenomenal job in explaining each step. It's created to be more of a walkthrough instead of you being thrown to the wolves and not really knowing where to begin.
- **Create a screenshot directory.** If you follow the "Run Your Recon More Effectively" trick below, you'll already have separate directories for each unique host. This means you can (and should) create a separate directory specific to hosting your screenshots for each unique host. Make sure you're almost taking "too many" screenshots. Every machine, every step, be sure to be taking screenshots and plenty of them. 
- **Watch/Read Hack The Box and TryHackMe walkthroughs.** This. Is. Important. Watch every Hack The Box video that ippsec and John Hammond has on their channels. Pay close attention to the methodology they use. In addition to this, read any additional writeups that you can find. Regardless of how easy you think a machine was, there's always another way to do it. There very well may be something that you might have missed or there's just a more advanced way to do things.
- **Take a snapshot.** Prevent running into issues like I did. Make sure you take a snapshot before your exam, but more importantly, make sure that everything is working so your snapshot is not useless.
- **If you think it sounds dumb, try it anyway.** So many times when doing Hack The Box or TryHackMe machines I've said to myself, "Nah, that's dumb, that won't work... wait, but will it?" It pays to try anyways because you never really know if that "dumb" turns into how you got the shell.

### Tricks
#### Enumeration Tricks
The biggest trick that I can give while enumerating is to use the proper keywords to your advantage. For example, if you found a service called VulnerableService 2.0.21, you can simply Google for:

```
VulnerableService 2.0.21 exploit
```

Is that not giving you the results you want? Try something like:

```
VulnerableService 2.0.21 poc
```

Or even:

```
VulnerableService 2.0.21 github
```

Or:

```
VulnerableService 2.0.21 python
```

I can almost sense the, "Duh, this is so obvious" eye-rolls, but I can tell you that I have attempted Googling a specific service with using one keyword, coming up short and thinking nothing was there, only to come back later on using different keywords and finding exactly what I needed. Even more specific, and why I mentioned this, I was doing a machine on Hack The Box and Googled something like "VulnerableService 2.0.21 exploit". Nothing came up, so I moved on. When I couldn't get anywhere on the machine, I came back to the service and Googled for "VulnerableService 2.0.21 python" and was able to find a python script on Packet Storm which got me a low privilege shell.

#### Run Your Recon More Effectively
Probably my favorite trick which helped me save tons of time was running [Interlace](https://github.com/codingo/Interlace) in conjunction with [nmapAutomator](https://github.com/21y4d/nmapAutomator). Interlace essentially enables single-threaded scripts or other applications to be multi-threaded. On the other hand, nmapAutomator is a super underrated reconnaissance script. To highlight some of its features:

* Runs Gobuster for you (automatically appends different extensions such as .php, .asp, etc depending on the application's response)...
* Runs all types of nmap scans for you (including UDP, script, vuln, and all ports)...
* Runs wpscan for you...
* Runs DNS recon for you...
* Runs nikto for you... 


Should I keep going? The point is, it's a fantastic tool and a massive time-saver -- especially when time is of the essence like in the OSCP exam. Just to further emphasize this point, the primitive way of running nmapAutomator (or any similar script, really) would be to run a bash one-liner on all your targets as follows:

```bash
for i in $(cat domains.txt); do bash nmapautomator.sh $i All; done
```

Instead of the above, we can use Interlace to our advantage and spawn different threads for each line in domains.txt and have them finish much faster! It's very easy to do since Interlace's syntax is incredibly easy. What specifically helped me was to run Interlace like so: 

```bash
interlace -tL targets.txt -threads 5 -c "bash nmapautomator.sh _target_ All" -v
```

#### Go For the Buffer Overflow First
By no means does this mean you have to do this. Do what you think will work best for you. At the end of the day, it's not about reading a blog post and doing everything they did, it's about tackling it in a way that is both effective and comfortable for you. Getting back on track, going for the Buffer Overflow machine first is great for several reasons, but most importantly, you can run your recon in the background while you go for the Buffer Overflow. Not to mention, if you follow the steps in the tips section regarding Buffer Overflows, this should be your easiest machine worth the most points.

#### Report Writing
Part of the report and what's needed from Offensive Security is to provide a detailed report which contains steps on how to reproduce your found vulnerabilities. Create a separate section in the report which fully details your steps taken, how you performed the steps, and *most importantly* how to reproduce. As I understand it, if your report isn't detailed enough to be reproduced by an Offensive Security team member, then you may lose points or receive zero points for a machine. Be sure to avoid this and be as detailed as possible.

Still on the topic of report writing, make sure you're **not** writing it like a Hack The Box writeup. In other words, try to stray away from:

> **Machine 1 --> User Shell was obtained through 'x' --> Privilege Escalation was obtained through 'y'**

If you find a vulnerability, regardless of if it provided a shell to you, throw it in the report! At the end of the day, this is meant to be realistic and like a real penetration test report, so try to structure it as such. 

Finally, the report is not meant to be glossed over. Make sure you spend a lot of time on it, there's a reason you're provided 24 hours. I remember reading one or two OSCP blogs prior to me taking my exam that mentioned they had more than enough points, but failed due to the report. It definitely can and does happen, it's your job to avoid it by being as detailed as possible.

## Final Notes
Stay calm and relax; you got this! It's not impossible, it's hard, but it's absolutely doable. Put in the work, study, enumerate and, of course, try harder! Good luck and happy hacking.

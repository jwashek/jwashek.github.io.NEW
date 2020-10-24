---
title: Cobalt Strike 4.0+ Malleable C2 Profile Guideline
author: bgib0ss
date: 2020-10-23 23:25:00 +0800
categories: [RedTeam, Cobalt_Strike]
tags: [cobalt strike]
---

## Intro

We are now in the Cobalt Strike 4.0+ era. As Cobalt Strike is getting more popular choice for the Command and Control (“C2”) server nowadays, customizing your malleable C2 profile is imperative to disguise your beacon traffics as well as communication indicators. Additionally, it can also help dictate in-memory characteristics and beacon process injection behaviors.

The full profile creation guide can be found here [CS4.0_guideline.profile](https://github.com/bigb0sss/RedTeam/blob/master/CobaltStrike/malleable_C2_profile/CS4.0_guideline.profile). It contains more details/instructions to craft the Malleable C2 profiles.

## Global Option Block

```
set sample_name "bigb0ss.profile";     
  # Profile name (used in the Indicators of Compromise report)

set sleeptime "30000";                  
  # Sleep time for the beacon callback (in milliseconds)
  
set jitter "50";                        
  # Jitter to set %. In this example, the beacon will callback between 15 and 30 sec jitter
  
set host_stage "[true|false]";            
  # Staged payload allow or disallow (Note: Stager payloads are generally easier to get caught, but it's necessary for the space-restricted situations)
  
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.177";    
  # User-Agent Setup
```


---
title: "Converting Tapes to MP3s"
date: 2010-12-06T08:00:00-04:00
draft: false
---

Like many others my age, I grew up on listening to cassette tapes. Tapes can get easily tangled and damaged, have a background hiss, and can only be listened to sequentially (you can't jump from song to song). There's one relatively new problem - nobody has tape players anymore. Repurchasing every tape you owned as an MP3 might not financially feasible at $15 per CD and some are simply unavailable.

I therefore decided to convert the tapes to MP3s myself. All I needed was a computer, wall-powered cassette player, a [stereo male to male 3.5mm cable](http://www.amazon.com/s/url=search-alias%3Daps&field-keywords=male+to+male+3.5mm), and [Audacity](https://www.audacityteam.org/download/), a free sound editing program. Considering that the cable runs for **less than $6**, it wasn't an expensive experiment.

The first thing I did was connect the cable to the *Line In* on my computer, and the headphone jack on the cassette player. Then I rewound the tape to the beginning, hit record on audacity, and hit play for the cassette player. When I heard the cassette stop, I simply flipped it in the player, and hit play again. After playback completed, I used the [Noise Removal](http://wiki.audacityteam.org/index.php?title=Noise_Removal) feature to remove the hiss, deleted quiet time before/after the tape itself, exported as mp3, and moved on the next tape.

However, this didn't go perfectly at first, so just a bit more before you start, so you can avoid the problems I encountered:

- I got a 12 foot cable because I didn't want the length to be an issue. However, if 6 feet is enough, you're better off with that, as a longer cable gives more opportunities for the signal to be damaged.
- Given a choice of a Mic input or Line In, to use the Line In, as there's less noise on that one (since Mic input supplies power).
- On my first recording, I had the volume output of the cassette player too high. If the input is too high, you'll see the entire area in audacity filled - that's bad. Adjust the volume so that the entire wave fits within the boundaries to ensure that the input isn't clipped. Don't make it too low though, since the hiss might become a significant part of your recording.
- Audacity stores the results of every single operation, to allow an unlimited (?) amount of undos. However, if you don't have a large amount of space free (more than 10 GB), Audacity can easily fill up your hard disk. When you close it, it will clean up all of its temp files and reclaim the space used by all the temporary files. Therefore, if you see your disk space running low (less than 1-2 GB depending on your total free space) I recommend that you close and re-open Audacity, which will free that space.
- The noise removal tool took me a few minutes to figure out, but the [wiki](https://support.audacityteam.org/repairing-audio/noise-reduction-removal) makes it simple enough: Select a portion from the beginning of the tape, where all you can hear is noise, hit "Effect -> Noise Removal" and "Get Noise Profile", then hit Control+A (Select all), "Effect -> Noise Removal" and "Remove Noise".
- Exporting as mp3 requires the LAME encoder, which Audacity can't include by default (mp3 licensing issues). There's a link to it on their download page (it points to [here](http://audacity.sourceforge.net/help/faq?s=install&item=lame-mp3)).
- I used 192 kbps mp3's. You can use a higher or lower bitrate, however, I felt that was most efficient, considering the input quality.


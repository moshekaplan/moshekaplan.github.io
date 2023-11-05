---
title: "Converting VHS Tapes to MP4s with ffmpeg"
date: 2015-05-12T23:14:27-04:00
draft: false
---

I thought it would be wise to digitize my family’s collection of home videos stored on VHS.

The first step was to try to research existing tools. I had gotten tvtime to display the video, but unfortunately, numerous threads (link) mentioned that there was no way to record from tvtime, and running a screen capture utility would be extremely inefficient. xawtv was mentioned in a few places (link), but it maxed at 384×288 and only supported AVI output, with minimal configuration available.

So I tried using VLC. VLC has an option to “Convert” a source video, which includes capture devices. But I ran into two issues:

1. Instead of the wonderful movie I expected to see, all I got was an ugly green screen
1. The sound was going into my Line In, not the sound card and I couldn’t get it to record the sound and video into a single file.

The first issue was particularly vexing, as the video displayed without issue when using tvtime. The issue was because the bt878 card I was using has multiple inputs (S-video, Composite, and TV), and I my video was coming in through the Composite, which was not the default input. I realized this when I tried using xawtv, and I iterated through the available inputs until the video displayed. So in VLC, all I had to do was view the advanced options and change the input to 1, instead of 0.

Ultimately, I couldn’t find a way to resolve the second issue with VLC. That’s where ffmpeg came in.

So first, to select the video device: I knew that the device was `/dev/video0`. But how could I select input 1, and not the default input 0?  The easiest solution I found was to use `v4l2-ctl` from the `v4l-utils` package to change the default input device:

```
v4l2-ctl --set-input=1
```

The next step was to record the Line In input. I started with [ffmpeg’s ALSA capture guide](https://trac.ffmpeg.org/wiki/Capture/ALSA). Unfortunately, that was the wrong path – as evidenced from the output of `arecord -L`:

```
moshe@moshe-desktop:~$ arecord -L

default
    Playback/recording through the PulseAudio sound server
null
    Discard all samples (playback) or generate zero samples (capture)
pulse
    PulseAudio Sound Server
...
```


So, next step was to get the list of PulseAudio devices:

```
moshe@moshe-desktop:~$ pactl list sources

Source #1
        State: SUSPENDED
        Name: alsa_input.pci-0000_00_14.2.analog-stereo
        Description: Built-in Audio Analog Stereo
        Driver: module-alsa-card.c
        Sample Specification: s16le 2ch 44100Hz
        Channel Map: front-left,front-right
        Owner Module: 5
        Mute: no
        Volume: 0:  56% 1:  56%
                0: -15.00 dB 1: -15.00 dB
                balance 0.00
        Base Volume:  32%
                     -30.00 dB
        Monitor of Sink: n/a
        Latency: 0 usec, configured 0 usec
        Flags: HARDWARE HW_MUTE_CTRL HW_VOLUME_CTRL DECIBEL_VOLUME LATENCY
        Properties:
                alsa.resolution_bits = "16"
                device.api = "alsa"
                device.class = "sound"
                alsa.class = "generic"
                alsa.subclass = "generic-mix"
                alsa.name = "ALC1200 Analog"
                alsa.id = "ALC1200 Analog"
                alsa.subdevice = "0"
                alsa.subdevice_name = "subdevice #0"
                alsa.device = "0"
                alsa.card = "0"
                alsa.card_name = "HDA ATI SB"
                alsa.long_card_name = "HDA ATI SB at 0xf9ff4000 irq 16"
                alsa.driver_name = "snd_hda_intel"
                device.bus_path = "pci-0000:00:14.2"
                sysfs.path = "/devices/pci0000:00/0000:00:14.2/sound/card0"
                device.bus = "pci"
                device.vendor.id = "1002"
                device.vendor.name = "Advanced Micro Devices, Inc. [AMD/ATI]"
                device.product.id = "4383"
                device.product.name = "SBx00 Azalia (Intel HDA)"
                device.form_factor = "internal"
                device.string = "front:0"
                device.buffering.buffer_size = "65536"
                device.buffering.fragment_size = "32768"
                device.access_mode = "mmap+timer"
                device.profile.name = "analog-stereo"
                device.profile.description = "Analog Stereo"
                device.description = "Built-in Audio Analog Stereo"
                alsa.mixer_name = "Realtek ALC1200"
                alsa.components = "HDA:10ec0888,1025014e,00100101"
                module-udev-detect.discovered = "1"
                device.icon_name = "audio-card-pci"
        Ports:
                analog-input-microphone-front: Front Microphone (priority: 8500, not available)
                analog-input-microphone-rear: Rear Microphone (priority: 8200, not available)
analog-input-linein: Line In (priority: 8100, available)
        Active Port: analog-input-linein
        Formats:
                pcm

```


So now we know our device is `alsa_input.pci-0000_00_14.2.analog-stereo` . So now we know enough to craft the following command:

```bash
ffmpeg -f pulse -i alsa_input.pci-0000_00_14.2.analog-stereo -i /dev/video0 ~/Desktop/out.mp4
```

Unfortunately, we’re not done. The video is low quality, the audio and video aren’t synced, and unless we close it ourselves, it’ll literally record until the hard disk is full.

```bash
ffmpeg  -f pulse -i alsa_input.pci-0000_00_14.2.analog-stereo -thread_queue_size 512 -async 12 -i /dev/video0  -strict -2 -q:v 1 -t 4:00:00 -y  ~/Desktop/out.mp4
```

From the docs:

* `-async 12`  # “Stretches/squeezes” the audio stream to match the timestamps, the parameter is the maximum samples per second by which the audio is changed.
* `-thread_queue_size 512` # maximum number of queued packets when reading from the file or device. With low latency / high rate live streams, packets may be discarded if they are not read in a timely manner; raising this value can avoid it.
* `-strict -2`  # This is to use the native FFmpeg AAC encoder. It’s not as good quality as other encoders, but fine enough for what I’m working with.
* `-q:v 1`  # Set the quality of the video to highest
* `-t 4:00:00`  # Record for up to 4 hours.
* `-y`  # overwrite the output file if it already exists

And now that we’ve ironed out all the issues:

![Convert all the videos!](001.jpeg)


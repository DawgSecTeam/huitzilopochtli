# sounds.CREDIT.md

`agent/sounds.py` embeds two notification sounds played on score change:

| constant          | plays when        | origin file                     |
|-------------------|-------------------|---------------------------------|
| `GAIN_WAV_B64`    | score went UP     | `sounds/gain.wav` (chime)       |
| `PENALTY_WAV_B64` | score went DOWN   | `sounds/alarm.wav` (klaxon)     |

Source: the community **CyberPatriot Soundboard**
(https://github.com/ErikBoesen/cpsoundboard, `gh-pages` branch), which
redistributes the notification sounds of the official **CyberPatriot
scoring engine**. Downloaded 2026-09-09; resampled with ffmpeg to
16-bit mono PCM (gain 22050 Hz, penalty 11025 Hz) to keep the zipapp
small. File sizes before resample matched the GitHub API listing
byte-for-byte (gain 263,252 B; alarm 110,294 B).

These recordings belong to the CyberPatriot program (Air Force
Association / AT&T), not to this repo or to the soundboard author (the
soundboard's MIT license covers its code, not the ripped audio). They
are vendored here solely so practice boxes sound like the real
competition environment. If you redistribute this repo outside a
training context, prefer replacing them with freely licensed
equivalents.

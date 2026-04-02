# \# js8-gridtracker-bridge



See JS8 activity on a map like FT8 — without stations broadcasting their location.



\## What this is



`js8-gridtracker-bridge` is a Python bridge between JS8Call and GridTracker.



It listens to JS8Call UDP output, looks up missing grid squares using HamQTH, and sends synthetic WSJT-X-style packets so GridTracker can display JS8 activity more like FT8.



\## What this is NOT



This does NOT turn JS8 into FT8.



\* JS8 is conversational and indirect

\* FT8 is structured and direct



This bridge is an \*\*interpretation layer\*\*, not a protocol conversion.



\## What you get



\* More stations visible on the map

\* Approximate distance awareness

\* Visibility into group traffic (@MAGNET, @GHOSTNET, etc.)

\* No need to query stations over the air for grid



\## Architecture



JS8Call → bridge → GridTracker



Typical ports:



\* JS8Call output: 127.0.0.1:2237

\* Bridge listen: 127.0.0.1:2237

\* Bridge output: 127.0.0.1:2240

\* GridTracker: 127.0.0.1:2240



\## Requirements



\* Python 3

\* requests (`pip install requests`)

\* JS8Call Improved with UDP enabled

\* GridTracker

\* HamQTH account



\## Setup



Install dependency:



pip install requests



Create credentials file:



\~/.config/js8\_gt\_bridge/hamqth.json



Example:



{

"user": "your\_username",

"password": "your\_password"

}



Protect it:



chmod 600 \~/.config/js8\_gt\_bridge/hamqth.json



\## Run



python js8\_to\_gridtracker\_bridge.py



If needed, stop old instance:



pkill -f js8\_to\_gridtracker\_bridge.py



\## Modes



Inside the script:



MODE = "network"



network:



\* shows most activity

\* includes indirect reports

\* best awareness



clean:



\* less clutter

\* more conservative



shadow:



\* debug only

\* no synthetic output



\## Known limitations



\* JS8 messages are not standardized like FT8

\* Some traffic is inferred, not exact

\* GridTracker controls final display

\* Some callsigns will fail lookup

\* Portable (/P) calls are normalized



\## License



MIT



\## Status



Experimental but functional.



This project explores better visualization of JS8 network activity.




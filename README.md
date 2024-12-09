# JWKS Server in python.
## Version
- Project3
## Updates:
- added AES encryption
- added auth logs
- added rate limiter
- added register post method
## Requirements:
- cryptography version: 43.0.1</li>
- pyjwt version:  2.8.0</li>
- set enviornment variable NOT_MY_KEY
## Directions:
- Open up your favorite browser
- navigate to http://localhost:8080/ to access the server
- (or just run gradebot IYKYK)
## Citations:
I acknowledge the use of AI during this assignment. the AI was mainly used to integrate the updating of auth log, the timeout class, and the AES password encryption. Prompts used (not including prompts to debug the AI generated code) include the following:
- add AES Encryption of Private Keys
- log post auth details into the DB table auth_logs
- implement a rate limiter that limits auth requests by 10 requests per second.
<p>The previous list is not exhaustive as there may have been other prompts to the AI that I may have forgotten to mention.</p>

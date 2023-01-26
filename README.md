# NoteApp
Secure note storing application where you can publicly share your notes or encrypt them!

How to use:
1. `docker build -t chojnicp/note-app . `
2. `docker run -d --name note-app -p 80:80 -p 443:443 chojnicp/note-app`

If you are going to use it, remember to replace https certs and provide another application secret key!

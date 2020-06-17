# tameshigiri
File carving utility for forensic recovery of image and documents for NYU Digital Forensics course assignment.

Tameshigiri takes two arguments in the command line, for two forensic disk
images. It returns a folder containing all of the recovered files, a single
sqlite database containing the following
 - filename
 - md5 hash
 - any extractable metadata
 A single report containing the same information as the database in human
 readable format
Build notes:
Kali version 5.2.0-kali2
Python version 2.7.17
pip version 18.1
Modules Required:
 -imagemounter
   'apt-get install python-setuptools xmount ewf-tools afflib-tools sleuthkit'
   'pip install imagemounter
   'imount --check' #Shows if your require any more libraries
 -pyPdf
  'pip install pyPdf'
 -exifread
  'pip install exifread'
Citations:
 - Relies heavily on imagemounter documentation and cli at github.com/ralphje/imagemounter
 - File carving inspired by example provided at thehexninja.com/2018/01/practical-exercise-image-carving-ii.html

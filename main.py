"""
CB4292 Charles Beddingfield Assignment 4
tameshigiri takes two arguments in the command line, for two forensic disk
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
"""
from imagemounter import *
import os
from os import path
import sys
import shutil
import imghdr
import magic
import pyPdf
import exifread
import hashlib
import sqlite3
import re

recovered_directory = './recovered/'
types_arr = ['rgb', 'gif', 'pbm', 'pgm', 'ppm', 'tiff', 'rast', 'xbm',
'jpeg', 'bmp', 'png', 'webp', 'exr', 'pdf']

def main():

    image_list = []
    #declares evidence dictionary to hold retrieved volume info modified by
    prepped_evidence = {}
    output_databases = []
    os.mkdir('./recovered')
    recovered_directory = './recovered/'
    types_arr = ['rgb', 'gif', 'pbm', 'pgm', 'ppm', 'tiff', 'rast', 'xbm',
    'jpeg', 'bmp', 'png', 'webp', 'exr', 'pdf']
    #minimal input checking
    arg_count = len(sys.argv)
    if arg_count < 3:
        print("No image file provided.")
        exit()
    """
    if arg_count > 4:
        print("Too many arguments.")
        exit()
    """
    #read in arguments, creates list, assuming they are proper images.
    for i, argument in enumerate(sys.argv):
        if i > 0:
            image_list.append(sys.argv[i])
            #print("Appending " + str(sys.argv[i]) + " to list.\n")
    #mounts files, make separate function?
    mountup(image_list, prepped_evidence)
    #probably won't work
    #Do some stuff, whatever.
    for vols in prepped_evidence['mounted_volumes']:
        print("Volume:")
        print(vols)
        scan(vols)
        #Create sqlite table for each volume
    #Begin analysis on recovered filenames
    print("Raw volumes now to be analyzed: ")
    for vol in prepped_evidence['unmounted_volumes']:
        print("Retrieving Raw volume" + vol)
        retrieve_raw(vol)
    print("Beginning Analysis loop.")
    connection = sqlite3.connect('Recovered Files.db')
    curse = connection.cursor()
    curse.execute('''CREATE TABLE Recovered_Files (id integer, filename text,
    md5hash text, metadata text)''')

    for index, filename in enumerate(os.listdir(recovered_directory)):
        filesize = os.path.getsize(recovered_directory+filename)
        if filesize != 0:
            file_row = []
            #file_row = []
            file_row.append(index)
            file_row.append(filename)
            analyze(file_row)
            curse.execute('insert into Recovered_Files values (?,?,?,?)', file_row)
        else:
            os.remove(recovered_directory+filename)
    #Clean up after yourself
    connection.commit()
    connection.close()
    clean_up(prepped_evidence['parse_struct'])


def mountup(image_array, evidence_dict):
    os.mkdir('/tmp/evidence/')
    parser = ImageParser(image_array, mountdir='/tmp/evidence', pretty=True)
    raw_images_only = []
    successful_mounts = []
    unmountable_list = []
    """
    artifacts = {
        #"mounted_volumes" :,
        #"unmounted_volumes" :,
        #"parse_struct" :
    }
    """
    #mount all mountable images
    for volume in parser.init():
        if volume.mountpoint:
               print("Volume " + str(volume.mountpoint) + " successfully\
                      mounted!\n")
               successful_mounts.append(volume.mountpoint)

    #creates a list of raw images that were not mounted
    for volume in parser.get_volumes():
        # print(str(volume.get_raw_path()))
        if str(volume.get_raw_path()).endswith('.raw'):
            unmountable_list.append(str(volume.get_raw_path()))
    #Check and store unmountable images
    # unmountable_list = []
    volume_list = parser.get_volumes()
    for item in volume_list:
        if not item.is_mounted:
            print("File "+ str(item) + " is not mounted, storing as raw.")
    print("Raw files will be scanned after mounted drives.\n")

    #Future feature: copies files, creates working directory, compares hashes
    #to original files
    evidence_dict['unmounted_volumes'] = unmountable_list
    evidence_dict['mounted_volumes'] = successful_mounts
    evidence_dict['parse_struct'] = parser
    # return artifacts

def clean_up(established_parser):
    #unmount function
    established_parser.clean()
    del established_parser
    os.rmdir('/tmp/evidence/')
#iterates through mounted volumes, passing each file to function checking type
def scan(volume):
    #generate list of files, place in dictionary
    for subfolders, folders, files in os.walk(volume):
        for file in files:
            name = subfolders + '/' + file
            # print(name)
            file_check(name, recovered_directory, types_arr)

#checks magic number of a file against a passed list of types
def file_check(filename, save_directory, desired_types_array):
    file_type = 'unknown'
    if os.path.getsize(str(filename)) == 0:
        return

    file_type = imghdr.what(str(filename))
    # print("After imghdr: " + file_type)
    if not file_type or file_type == 'unknown':
        # print("Trying magic")
        file_type = magic.from_file(str(filename), mime=True)
        # print("Magic says " + str(filename) + " is of file type "+ file_type)

    # print(str(filename))
    # print("Can't determine file type of " + filename + "!")
    # print("Type is "+ str(file_type) + ".")
    for type in types_arr:
        if file_type and file_type.endswith(type):
            print("Exporting " + str(filename) + " to recovered folder!")
            new_name = save_directory + str(os.path.basename(filename)) + '.' + type
            shutil.copyfile(filename, new_name)

def analyze(row_array):
    #processes an array for each file which will later be plugged into sql table
    #Analyzes PDFs
    metadata = ''
    filename = recovered_directory+row_array[1]

    if row_array[1].endswith('pdf'):
        try:
            current = pyPdf.PdfFileReader(file(filename, 'rb'))
            metadata = current.getDocumentInfo()
        except:
            pass
    #Analyzes anything else, i.e.images.
    else:
        current = open(filename, 'rb')
        metadata = exifread.process_file(current)
        #print(metadata)

        current.close()

    #generate hash value AFTER analysis, load into array
    hash_val = hashlib.md5(open(filename, 'rb').read()).hexdigest()
    row_array.append(hash_val)
    row_array.append(metadata)
    prettyDisplay(row_array)

def prettyDisplay(file_array):
    divider = '-'
    file_index = file_array[0]
    filename = file_array[1]
    hash_value = file_array[2]
    metadata = file_array[3]
    print(divider * 3 + "Analysis of: " + filename + divider * 3 + "\n")
    print("Database Index: "+ str(file_index) + "\n")
    print("File metadata:\n")
    #Formatter for pdf metadata
    if (filename.endswith('pdf')) and (metadata != None):
        for entry in metadata:
            print(entry+ ': ' + str(metadata[entry]))
    #formatter for image metadata
    else:
        if metadata != None:
            for entry in metadata.keys():
                if entry not in ('JPEGThumbnail', 'TIFFThumbnail'):
                    print("%s: %s" % (entry, metadata[entry]))

    print("\nMD5 Hash: " + hash_value + "\n")
    file_array[3] = str(file_array[3])

def retrieve_raw(filename):
    print(filename)
    trunc_file = str(os.path.basename(filename))
    print(trunc_file)
    start_magic_numbers = {'jpeg' : b'\xFF\xD8\xFF\xE0', 'pdf' : b'\x25\x50\x44\x46\x2D', 'gif' : b'\x47\x49\x46\x38\x39\x61'}
    end_magic_numbers = {'jpeg' : b'\xFF\xD9', 'pdf' : b'\x25\x25\x45\x4F\x46', 'gif' : b'\x00\x3B'}
    raw_vol = open(filename, 'rb')
    data = raw_vol.read()
    for key in start_magic_numbers:
        Start_offsets = [match.start() for match in re.finditer(re.escape(start_magic_numbers[key]),data)]
        End_offsets = [match.start() for match in re.finditer(re.escape(end_magic_numbers[key]),data)]
        number_of_starts = len(Start_offsets)
        number_of_ends = len(End_offsets)
        #traverses lists in normal order if not a pdf
        if key != 'pdf':
            f_number = 0
            for start_number in Start_offsets:
                try:
                    end_number = End_offsets[f_number]
                except IndexError:
                    end_number = start_number + 20000000
                if end_number < start_number:
                    end_number = start_number + 20000000
                carved_bytes = data[start_number:end_number+2]
                carved_name = trunc_file+str(start_number)+"-"+str(end_number)+"."+key
                carved_object = open(recovered_directory+carved_name, 'wb')
                carved_object.write(carved_bytes)
                carved_object.close()
                f_number +=1
        #Traverses lists backwards a la scalpel if looking for pdfs.
        else:
            f_number = len(Start_offsets) - 1
            # print("Number of start offsets"+ str(len(Start_offsets)))
            for end_number in reversed(End_offsets):
                if f_number >= 0:
                    start_number = Start_offsets[f_number]
                    carved_bytes = data[start_number:end_number+10]
                    carved_name = trunc_file+str(start_number)+"-"+str(end_number)+"."+key
                    carved_object = open(recovered_directory+carved_name, 'wb')
                    carved_object.write(carved_bytes)
                    carved_object.close()
                    f_number -=1#works backward through list of start numbers
    raw_vol.close()





if __name__=="__main__":
    main()

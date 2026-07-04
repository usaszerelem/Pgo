Obfuscate:
-input=./Test/Sample.txt
-output=./Test/Sample.dat
-mode=obfuscate
-password=HelloWorld

Reverse:
-input=./Test/Sampledat
-output=./Test/Sample3.txt
-mode=reverse
-password=HelloWorld

Obfuscate using external file for password:
-input=./Test/Sample.txt
-output=./Test/Sample.dat
-mode=obfuscate
-passwordfile=./Test/Bible.txt
-passwordoffset=100
-passwordlength=10

Reverse using external file for password:
-input=./Test/Sample.dat
-output=./Test/Sample2.txt
-mode=reverse
-passwordfile=./Test/Bible.txt
-passwordoffset=100
-passwordlength=10
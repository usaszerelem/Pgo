Obfuscate:
-input=./Test/Sample.txt
-output=./Test/Sample.dat
-mode=obfuscate

Reverse:
-input=./Test/Sampledat
-output=./Test/Sample3.txt
-mode=reverse

Obfuscate using external file for password:
-input=./Test/Sample.txt
-output=./Test/Sample.dat
-mode=obfuscate
-passwordfile=./Test/LargeFile.txt
-passwordoffset=100
-passwordlength=10

Reverse using external file for password:
-input=./Test/Sample.dat
-output=./Test/Sample2.txt
-mode=reverse
-passwordfile=./Test/LargeFile.txt
-passwordoffset=100
-passwordlength=10

Run tests any time with:

cmake --build build/debug
ctest --test-dir build/debug --output-on-failure

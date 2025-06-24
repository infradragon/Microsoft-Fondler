## this script is for me and has my preferences so if you dont like it go kick rocks
# if you are on windows 11 24h2, this script will break steam because the implementation of bbrv2 in 24h2 is completely broken. the solution is to not use 24h2 because its just too buggy.
This is only meant for desktop x86_64 Windows 10 and 11.
The script requires a restart to fully apply.

I cannot figure out how to remove some default apps on windows 11 (spotify, linkedin, whatsapp, etc) as they dont appear as appx packages, so you will have to remove them manually.
https://answers.microsoft.com/en-us/windows/forum/all/uninstall-pre-not-installed-spotify-whatsapp-etc/328d585c-9764-4407-9fac-f57c78b0dade


# how ts works
this is a batch script (.bat or .cmd), so you can think of every line like its being typed into a command prompt one by one.

everything until line 32 is boilerplate sanity checks i stole from the lovely ladies over at [massgrave](https://github.com/massgravel/) as well as setting the text color and window title.

line 34 first checks if its running as the user `S-1-5-18` (TrustedInstaller), and if it's not, it calls the function `:RunAsTI` which is that huge block of text at the very end of the script. it's a pre-made [function by AveYo](https://github.com/AveYo/LeanAndMean/blob/main/RunAsTI.bat) that runs stuff as TrustedInstaller.

the script then asks the user to set the value of two variables: `dclass` and `uclass`. they will be used later to set different options depending on what you input.

everything until line 869 is pretty simple batch, it just sets a bunch of options and they're all labeled.

the uninstall onedrive script is stolen from somewhere and i dont remember where

i wrote the script at line 917, it basically makes an array that has all the names of packages you want to uninstall, then counts the amount of items in the array, then for each item in the array it runs a powershell command to uninstall that item.

at line 1038 begins the options that can be set depending on your input at the beginning of the script with the `dclass` and `uclass` variables. they can both equal 1 or 2 depending on your input. it checks if the variable for that section is equal to to the number for the ***other*** option, and if it is, it skips it. so if `dclass=1`, and it gets to the section for device class 2, it sees that its equal to one and skips the section two. this logic is stupid and only works because each option has two possible values, but its easy to write. you can do it yourself better if you want to by checking if the value ***isn't*** equal to the value required for that section and if so it skips it.
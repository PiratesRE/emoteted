# Emotet'ed (toolkit)

This code is just a fun, developed for the need for the articles devoted to Emotet.

The sample directory contain real Emotet malware.
- the password is always: **infected**

**/!\ PLEASE, DO NOT USE FOR CRIMINAL PURPOSE BUT FOR THE RESHEARCH**

## unpacker.py
You can unpack the Emotet v5 (only) payload with the unpacker script.

```
$ python2.7 unpacker.py -h
usage: unpacker.py [--sample SAMPLE] [--out-file OUT_FILE]
                   [--out-stage1 OUT_STAGE1]

Emotet 2019 - Unpacking Payload Toolkit

required arguments:
  --sample SAMPLE, -s SAMPLE
                        Path to sample file to input.
  --out-file OUT_FILE, -of OUT_FILE
                        Path to unpacked file out.

optional arguments:
  --out-stage1 OUT_STAGE1, -os1 OUT_STAGE1
                        Path to stage1 file out.
```

![alt text][unpack_emotetv5]

## get_config.py

You can use the script "get_config.py" to get the IP addresses list.

```
$ python2.7 get_config.py -h
usage: get_config.py [--sample SAMPLE]

Emotet 2019 - Get Configuration Toolkit

required arguments:
  --sample SAMPLE, -s SAMPLE
                        Path to sample file to input.
```

== Emotet (version 5) ==

![alt text][ida_emotetv5]

![alt text][config_emotetv5]

== Emotet (version 6) ==

![alt text][ida_emotetv6]

![alt text][config_emotetv6]

[unpack_emotetv5]: https://raw.githubusercontent.com/PiratesRE/emoteted/master/pictures/demo-01.png "unpacker.py: Emotet (version 5)"

[config_emotetv5]: https://raw.githubusercontent.com/PiratesRE/emoteted/master/pictures/demo-02.png "get_config.py: Emotet (version 5)"
[config_emotetv6]: https://raw.githubusercontent.com/PiratesRE/emoteted/master/pictures/demo-03.png "get_config.py: Emotet (version 6)"

[ida_emotetv5]: https://raw.githubusercontent.com/PiratesRE/emoteted/master/pictures/demo-04.png "Emotet (version 5) | IP addresses localization"
[ida_emotetv6]: https://raw.githubusercontent.com/PiratesRE/emoteted/master/pictures/demo-05.png "Emotet (version 6) | IP addresses localization"

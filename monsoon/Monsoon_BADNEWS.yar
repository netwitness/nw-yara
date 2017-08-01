rule Monsoon_BADNEWS
{
  meta:
    author = "RSA Research - EMH - <NetWitness.Content@rsa.com>"
    description = "BADNEWS malware as described here - https://attack.mitre.org/wiki/Software/S0128"
    date = "21 July 2017"
  strings:
    $mz       = "MZ"
    $delay    = { 8? C6 99 F7 F9 85 D2 74 05 41 3B CF 7E F2 3B CE 75 0F 56 68 ?? ?? ?? ?? E8 ?? F8 FF FF 83 C4 08 43 46 81 FB 80 38 01 00 7E C6 }
    $encoded1 = "lfsofm43/emm"
    $encoded2 = "bewbqj43/emm"
    $encoded3 = "ouemm/emm"
    $decoder  = { C0 E0 0? 02 C1 34 ?? C0 C0 ?? 88 04 }
  condition:
    $mz at 0 and all of ($encoded*) and ($delay or $decoder)
}
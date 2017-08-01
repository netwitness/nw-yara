rule Monsoon_RTF_Dropper
{
  meta:
    author = "RSA Research - EMH - <NetWitness.Content@rsa.com>"
    description = "Actor likely using generic CVE-2015-1642 described here https://www.greyhathacker.net/?p=911"
    date = "21 July 2017"
  strings:
    $rtf  = { 7B 5C 72 74 66 31 5C 61 64 65 66 6C 61 6E 67 31 30 32 35 5C 61 6E 73 69 5C 61 6E 73 69 63 70 67 31 32 35 32 5C 75 63 31 5C }
    $pk   =  "504b0304"
    $ax1  =  "776f72642f616374697665582f61637469766558312e62696e"
    $ax2  =  "776f72642f616374697665582f61637469766558322e62696e"
    $xml1 = { 3631363337343639373636353538????????3265373836643663 }
 
  condition:
    $rtf at 0 and $pk and all of ($ax*) and #xml1 >  200
}

Pegasus Android Detector - detection data
=========================================

This directory holds the detection definitions.

1) STIX 2.1 indicator files (*.stix2) - MVT compatible
   Loaded automatically. Recognised pattern types:
     [domain-name:value='...']
     [ipv4-addr:value='...']   [ipv6-addr:value='...']
     [url:value='...']         [email-addr:value='...']
     [file:hashes.'SHA-256' = '...'] / 'SHA-1' / 'MD5'
     [file:path='...']         [file:name='...']
     [android-package-name:value='...']
     [android-property:name='...']
     [process:name='...']
     [x509-certificate:hashes.'SHA-256' = '...'] / 'SHA-1'

   Included files:
     pegasus.stix2            NSO Group Pegasus IoCs (Amnesty International)
     android_campaign.stix2   Android mercenary-spyware campaign IoCs (Amnesty / Google)

   Sources (as indexed by https://github.com/mvt-project/mvt-indicators):
     https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/pegasus.stix2
     https://raw.githubusercontent.com/AmnestyTech/investigations/master/2023-03-29_android_campaign/malware.stix2

2) Family-based rule files (*.txt)
   Optional. One "key: value" pair per line; a "family:" line starts a block.
     family: <name>
     name: <display name>
     severity: low|medium|high|critical
     package: <wildcard pattern>
     sha256: <hex>  sha1: <hex>  md5: <hex>
     cert: <substring>         cert_sha256: <hex>
     lib: <libname.so>         asset: <relative path>
     perm: <android.permission.XXX>
     string: <substring>  class: <substring>
     domain: <substring>  ip: <substring>  url: <substring>  email: <substring>

   Hard indicators (package / sha256 / sha1 / md5 / cert / cert_sha256 / lib /
   asset) match a family on their own. Soft indicators (perm / string / class)
   need at least 2 hits in the same block.

   Lines starting with '#' are comments.

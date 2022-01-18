#### Parser Content
```Java
{
Name = proofpoint-dlp-email-from
  Vendor = Proofpoint
  Product = Proofpoint TAP/POD
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ" 
  Conditions = [ """msgid""", """"cipher"""", """"pps"""", """"from"""", """:""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"relay"{1,20}:\s{0,100}"{1,20}({host}[\w\-.]{1,2000}?)\.?\s{0,100}\[({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"from"{1,20}:\s{0,100}"{1,20}<?({sender}[^@]{1,2000}@({external_domain_sender}[^"\s\>,;]{1,2000}))"{1,20

}
```
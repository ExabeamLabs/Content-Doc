#### Parser Content
```Java
{
Name = azure-email-notification
   Vendor = Microsoft
   Product = Microsoft
   Lms = Splunk
   DataType = "dlp-email-alert"
   TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
   Conditions = [  """ DOMAIN=""", """ RECIPIENT=""", """ SENDER=<>""" ]
   Fields = [
      """exabeam_host=([^=]+@\s*)?({host}\S+)""",
      """\sDOMAIN=({domain}[^\s]+)\s""",
      """\sSENDER=(<>|({sender}[^\s]+))\s""",
      """\sRECIPIENT=({recipient}[^\s]+)\s""",
      """\sSUBJECT=({subject}.+?)\s*\w+=""",
      """\sSIP=({src_ip}[^\s]+)\s""",
      """\sSIZE=({bytes}\d+)""",
      """\sSESSID=({user_sid}[^\s]+)\s""",
      """\sTS=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)""",
      """\sSTATUS=({outcome}[^\s]+)""",
   ]
}
```
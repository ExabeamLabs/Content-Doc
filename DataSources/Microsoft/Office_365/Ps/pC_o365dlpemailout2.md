#### Parser Content
```Java
{
Name = o365-dlp-email-out-2
  Conditions = [ """"Workload""", """"ClientProcessName"""", """"Subject"""", """"SendAs"""" ]

o365-dlp-email-out = {
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
    """"CreationTime\\*"{1,20}:[\s\\]{0,2000}"{1,20}({time}[^"\\]{1,2000})""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"host\\*"{1,20}:[\s\\]{0,2000}"{1,20}({host}[^"\\]{1,2000})""",
    """"UserId\\*"{1,20}:[\s\\]{0,2000}"{1,20}({user_email}[^"\\@]{1,2000}@[^"\\@]{1,2000})""",
    """"ResultStatus\\*"{1,20}:[\s\\]{0,2000}"{1,20}({outcome}[^"\\]{1,2000})""",
    """"ClientIPAddress\\*"{1,20}:[\s\\]{0,2000}"{1,20}\[?({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"MailboxOwnerUPN\\*"{1,20}:[\s\\]{0,2000}"{1,20}({sender}[^"\\]{1,2000})""",
    """"SendAsUserSmtp\\*"{1,20}:[\s\\]{0,2000}"{1,20}({additional_info}[^"\\]{1,2000})""",
    """"SendOnBehalfOfUserSmtp\\*"{1,20}:[\s\\]{0,2000}"{1,20}({additional_info}[^"\\]{1,2000})""",
    """"Attachments\\*"{1,20}:[\s\\]{0,2000}"{1,20}\s{0,100}({attachments}[^"\\]{1,2000})\s{0,100}""",
    """"Attachments\\*"{1,20}:[\s\\]{0,2000}"{1,20}\s{0,100}({attachment}[^"\\;]{1,2000})\s{0,100}""",
    """"Subject\\*"{1,20}:[\s\\]{0,2000}"{1,20}\s{0,100}({subject}[^"\\]{1,2000}?)\s{0,100}\\"""",
    """"ClientInfoString\\*"{1,20}:[\s\\]{0,2000}"{1,20}Client\\*=({alert_name}[^"\\;]{1,2000})""",
    """src-account-name":"({account_name}[^"]{1,2000})"""
  ]
  DupFields = [ "alert_name->alert_type" 
}
```
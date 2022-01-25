#### Parser Content
```Java
{
Name = s-digitalguardian-dlp-email-out-3
  Conditions = [ """Operation="Send Mail"""" , """Agent_UTC_Time=""" ]

splunk-digitalguardian-dlp-email-out = {
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Fields = [
    """(\s|exabeam_\w+=)?(Agent_UTC_Time|Server_UTC_Timestamp)="({time}\d{1,100}\/\d{1,100}\/\d\d\d\d \d{1,100}:\d{1,100}:\d{1,100} (am|AM|pm|PM))"""",
    """exabeam_host=([^@=]{1,2000}?@\s{0,100})?({host}[^\s]{1,2000})""",
    """(\s|exabeam_\w+=)Computer_Name ="([^\/\\"]{1,2000}[\\\/])?({host}[^"]{1,2000})"""",
    """(\s|exabeam_\w+=)User_Name ="(?:|(({domain}[^"\/\\]{1,2000})[\/\\]{1,2000})?({user}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Domain_Name ="(?:|({domain}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Email_Sender="(?:|({sender}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Email_Address="(?:|({sender}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Email_Recipient="([^"]{1,2000}\-)?({recipients}({recipient}[^"@\s;,]{1,2000}@[^"@\s;,]{1,2000}[^"]{0,2000}))"""",
    """(\s|exabeam_\w+=)Destination_File="(?:|({file_name}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Destination_File="(?:|message body|({attachment}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Destination_File_Extension="(?:|({extension}[^"]{1,2000}))"""",
    """(\s|exabeam_\w+=)Email_Subject="(?:|({subject}[^"]{1,2000}?))\s{0,100}"""",
    """(\s|exabeam_\w+=)Bytes_Read="(?:|({bytes}[^"]{1,2000}))"""",
    """Operation(_ID)?="({event_code}[^"]{1,2000})""""
  ]
  DupFields = [ "sender->email_user", "recipient->external_address" ]
  SOAR {
    IncidentType = "dlp"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "sender->dlpUser", "sender->emailFrom", "subject->emailSubject", "recipients->emailTo", "file_name->dlpFileName", "bytes->dlpFileSize"]
    NameTemplate = """Digital Guardian DLP Email Alert ${subject} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="user", Name ="email", Fields=["sender->email"]}
    
}
```
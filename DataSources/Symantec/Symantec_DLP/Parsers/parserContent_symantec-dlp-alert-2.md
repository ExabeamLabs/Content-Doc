#### Parser Content
```Java
{
Name = symantec-dlp-alert-2
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""INCIDENTID=""", """, blocked="""", """, policy="""", """, sender="""", """, severity=""""]
  Fields = [
    """detection_date="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """hostname="({src_host}[^"]{1,2000})"""",
    """INCIDENTID="({alert_id}\d{1,100})"""",
    """severity="({alert_severity}\d{1,10})"""",
    """policy="({alert_name}[^"]{1,2000})"""",
    """username="(({domain}[^\\"]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """domain="({domain}[^"]{1,2000})"""",
    """sender="({user_email}[^"@]{1,2000}@[^"]{1,2000})"""",
    """recipients="({target}[^"@]{1,2000}@[^"]{1,2000})"""",
    """subject="\s{0,100}({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """blocked="({outcome}\d{1,100})""""
  ]
  DupFields = [ "alert_name->alert_type"]
}
```
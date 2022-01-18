#### Parser Content
```Java
{
Name = pan-alert-1
  Vendor = Palo Alto Networks
  Product = WildFire
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """,THREAT,wildfire-virus,""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """\d\d:\d\d:\d\d\s({host}[\w.-]{1,2000})\s""",
    """THREAT,([^,]{1,2000

}
```
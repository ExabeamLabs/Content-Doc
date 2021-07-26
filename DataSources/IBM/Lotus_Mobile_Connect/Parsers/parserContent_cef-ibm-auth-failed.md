#### Parser Content
```Java
{
Name = cef-ibm-auth-failed
  Vendor = IBM
  Product = Lotus Mobile Connect
  Lms = ArcSight
  DataType = "authentication-failed"
  TimeFormat = "epoch"
  Conditions = [ """|IBM|HQ_LMC|""", """|LMC_Login_Failure|""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """rt=({time}\d{1,100})""",
    """dvc=({host}[a-fA-F:\d.]{1,2000})""",
    """dvchost=({host}[\w\-.]{1,2000})""",
    """shost=({src_host}[\w\-.]{1,2000})""",
    """src=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """dhost=({dest_host}[\w\-.]{1,2000})""",
    """dst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """suser=({user}\S+)""",
    """deviceOutboundInterface=({src_network_type}.+?)\s{0,100}(\w+=|$)"""
  ]
}
```
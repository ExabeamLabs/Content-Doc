#### Parser Content
```Java
{
Name = cef-ibm-auth-successful
  Vendor = IBM
  Product = Lotus Mobile Connect
  Lms = ArcSight
  DataType = "authentication-successful"
  TimeFormat = "epoch"
  Conditions = [ """|IBM|HQ_LMC|""", """|LMC_Login_Success|""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """rt=({time}\d{1,100})""",
    """dvc=({host}[a-fA-F:\d.]+)""",
    """dvchost=({host}[\w\-.]+)""",
    """shost=({src_host}[\w\-.]+)""",
    """src=({src_ip}[a-fA-F:\d.]+)""",
    """dhost=({dest_host}[\w\-.]+)""",
    """dst=({dest_ip}[a-fA-F:\d.]+)""",
    """suser=({user}\S+)""",
    """deviceOutboundInterface=({src_network_type}.+?)\s{0,100}(\w+=|$)"""
  ]
}
```
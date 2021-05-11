#### Parser Content
```Java
{
Name = netmotion-vpn-end
    Vendor = NetMotion Wireless
  Product = NetMotion Wireless
    Lms = Splunk
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ "Disconnect", "Log_Date_Time" ]
    Fields = [
      """Log_Date_Time=({time}\d{1,100})""",
      """exabeam_host=({host}[^\s]+)""",
      """Device_Name="{1,20}({src_host}[^"]+)""",
      """User_Name="{1,20}([^\\]+\\)?({user}[^"]+)"""
    ]
  }
```
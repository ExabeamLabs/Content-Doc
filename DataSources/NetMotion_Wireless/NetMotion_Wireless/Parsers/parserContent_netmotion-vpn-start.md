#### Parser Content
```Java
{
Name = netmotion-vpn-start
    Vendor = NetMotion Wireless
  Product = NetMotion Wireless
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "POP_Address=", "Log_Date_Time" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """Log_Date_Time=({time}\d{1,100})""",
      """Device_Name="{1,20}({src_host}[^"]+)""",
      """User_Name="{1,20}([^\\]+\\)?({user}[^"]+)""",
      """POP_Address="{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Virtual_Address="{1,20}({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = ["user->account"]
  }
```
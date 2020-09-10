#### Parser Content
```Java
{
Name = netmotion-vpn-start
    Vendor = NetMotion Wireless
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "POP_Address=", "Log_Date_Time" ]
    Fields = [
      """exabeam_host=({host}[^\s]+)""",
      """Log_Date_Time=({time}\d+)""",
      """Device_Name="+({src_host}[^"]+)""",
      """User_Name="+([^\\]+\\)?({user}[^"]+)""",
      """POP_Address="+({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """Virtual_Address="+({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
  }
```
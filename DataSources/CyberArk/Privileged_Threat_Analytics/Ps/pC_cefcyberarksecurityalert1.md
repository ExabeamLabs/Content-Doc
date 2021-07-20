#### Parser Content
```Java
{
Name = cef-cyberark-security-alert-1
   Vendor = CyberArk
   Product = Privileged Threat Analytics
   Lms = Splunk
   DataType = "alert"
   TimeFormat = "epoch"
   Conditions = [ """CyberArk|PTA""" , """suser=""" ]
   Fields = [
      """deviceCustomDate1=({time}[^\s]{1,2000})"""
      """\s({host}[^\s]{1,2000})\sCEF"""
      """shost=((None)|({src_host}[^\s]{1,2000}))""",
      """src=((None)|({src_ip}[^\s]{1,2000}))""",
      """dst=((None)|({dest_ip}[^\s]{1,2000}))""",
      """suser=((None)|({user}[^\s\(]{1,2000}))""",
      """dhost=((None)|({dest_host}[^\s]{1,2000}))""",
      """duser=((None)|({additional_info}[^\s\(]{1,2000}))""",
      """cs2=({alert_id}[^\s]{1,2000})""",
      """CEF[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_type}[^\|]{1,2000})""",
      """CEF[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|[^|]{1,2000}?\|({alert_name}[^\|]{1,2000})\|({alert_severity}[^\|]{1,2000})"""
   ]
}
```
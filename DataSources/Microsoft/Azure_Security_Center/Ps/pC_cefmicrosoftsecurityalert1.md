#### Parser Content
```Java
{
Name = cef-microsoft-security-alert-1
  DataType = "security-alert"
  Conditions = [ """CEF:""", """"category":""", """"MCAS_ALERT_UEBA_INVESTIGATION_PRIORITY_INCREASE"""", """"title":""", """"vendor":""", """"Microsoft"""", """"provider":""" ]

cef-azure-alert = {
    Vendor = Microsoft
    Product = Azure Security Center
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
    Fields = [
    """"eventDateTime":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{2}(\.\d{1,7})?Z)"""
    """"title":"({alert_name}[^"]{1,2000})""""
    """"userPrincipalName":\s{0,100}"([-|\\|<]|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))>?""""
    """"severity":"({alert_severity}[^"]{1,2000})""""
    """"domainName":"({domain}[^"]{1,2000})""""
    """"id":"({alert_id}[^"]{1,2000})""""
    """msg=({additional_info}[^=]{1,2000}?)\s\w+="""
    """"category":"({alert_type}[^"]{1,2000})""""
    """"accountName":"({user}[^"]{1,2000})""""
    
}
```
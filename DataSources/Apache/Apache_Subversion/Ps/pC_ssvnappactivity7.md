#### Parser Content
```Java
{
Name = s-svn-app-activity-7
  Product = Apache Subversion
  Conditions = [ """"PUT /svn/""" ]

svn-app-activity = {
  Vendor = Apache
  Lms = Splunk
  DataType = "app-activity"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Fields = [
    """({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\s{0,100}[^\s]{1,2000}\s{0,100}({user}[^\s]{1,2000})\s{0,100}\[({time}\d{1,100}\/\w+\/\d{1,100}:\d{1,100}:\d{1,100}:\d{1,100}\s{0,100}\-\d{1,100})\]\s{0,100}"({additional_info}({activity}[^"\s]{1,2000})\s({object}[^\s"]{1,2000}).*?)"\s{0,100}(?:-|({result}\d{1,100}))\s{0,100}(?:-|({bytes}\d{1,100}))\s{1,100}[^\s]{1,2000}\s{1,100}"({user_agent}[^"]{1,2000})"""",
    """({app}svn)"""
  
}
```
#### Parser Content
```Java
{
Name = github-app-activity-12
   Conditions = [ """team.change_privacy,""" ]

github-app-activity = {
  Vendor = GitHub
  Product = GitHub
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_raw=({activity}[^,]{1,2000}),({user}[^,]{1,2000}),(?:\s{0,100}|({resource}[^,]{0,2000})),[^,]{0,2000},(?:\s{0,100}|({object}[^,]{0,2000})),({time}\d{1,100}),[^,]{0,2000},(?:\s{0,100}|("{0,20}\[)?({additional_info_2}[^\[\]]{0,2000})(\]"{0,20})?),([^,]{0,2000},){3}(?:\s{0,100}|({additional_info_1}.*?))\s{0,100}$"""
  
}
```
#### Parser Content
```Java
{
Name = cef-crowdstrike-alert
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ "CEF", """|CrowdStrike|FalconHost|""" ]
    Fields = [ 
      """exabeam_host=({host}[\w\-.]+)""",
      """\srt=({time}\d{1,100})""",
      """({host}[\w.\-]+) CEF:""",
      """\s({host}[^\s]+)\s{1,100}CrowdStrike Falcon""",
      """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdvchost=({host}[^\s]+)""",
      """(\s|\|)(s|d)ntdom=(?:N\/A|({domain}[^\s]+))""",      
      """(\s|\|)suser=(?:N\/A|({user}.+?))(@({domain}.+?))?\s{1,100}(\w+=|$)""",
      """(\s|\|)duser=(?:N\/A|({user}.+?))(@({domain}.+?))?\s{1,100}(\w+=|$)""",
      """(\s|\|)dhost=({src_host}[^\s]+)""",
      """(\s|\|)shost=({src_host}[^\s]+)""",
	  """(\s|\|)shost=.+?(\s|\|)dhost=({dest_host}[^\s]+)""",
      """(\s|\|)dhost=({dest_host}[^\s]+).+?(\s|\|)shost=""",
      """(\s|\|)src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """(\s|\|)dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """CrowdStrike\|([^|]+\|){3}({alert_name}[^|]+)""",
      """CrowdStrike\|([^|]+\|){2}({alert_type}[^|]+)""",
      """CrowdStrike\|([^|]+\|){4}({alert_severity}[^|]+)""",
	  """(\s|\|)cat=({alert_name}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)cs3=({alert_name}.+?)\s{1,100}\w+=.*?cs3Label=ScanResultName""",
      """cs3Label=ScanResultName.*?cs3=({alert_name}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)cs1=({alert_name}.+?)\s{1,100}\w+=.*?cs1Label=ScanResultName""",
      """cs1Label=ScanResultName.*?cs1=({alert_name}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)msg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)fname=({file_name}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)filePath=({file_path}.+?)\s{1,100}(\w+=|$)""",
      """(\s|\|)cs1=("{1,20})?({command_line}.+?)("{1,20})?\s\w+=.*(?=cs1Label=CommandLine)""",
      """(?=cs1Label=CommandLine).*cs1=("{1,20})?({command_line}.+?)("{1,20})?\s{1,100}(\w+=|$)""",
      """(\s|\|)cs5=("{1,20})?({command_line}.+?)("{1,20})?\s\w+=.*(?=cs5Label=CommandLine)""",
      """(?=cs5Label=CommandLine).*cs5=("{1,20})?({command_line}.+?)("{1,20})?\s{1,100}(\w+=|$)""",
      """(\s|\|)cs6=({falcon_host_link}.+?)\s\w+=.*(?=cs6Label=FalconHostLink)""",
      """(?=cs6Label=FalconHostLink).*cs6=({falcon_host_link}.+?)\s{1,100}(\w+=|$)"""
    ]
    DupFields = ["falcon_host_link->additional_info"]
  }
```
#### Parser Content
```Java
{
Name = n-forwarded-cef-mcafee-epo
    Vendor = McAfee
    Product = McAfee Endpoint Security
    Lms = NitroCefSyslog
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """|McAfee|ESM|""", """|367-""" ]
    Fields = [ """\send=({time}\d{1,100}).*\snitroThreat_Category=(?!ops\.task\.cancel|hip\.file|None)""",
      """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sshost=({src_host}[^\s]{1,2000})""",
      """\|McAfee\|ESM\|[^\|]{1,2000}\|367-({signature_id}[^\|]{1,2000})\|({alert_type}[^\|]{1,2000}).*?\seventId=({alert_id}[^\s]{1,2000}).*\snitroThreat_Name=({alert_name}.+?)\s[^\s]{1,2000}?=""",
      """\sduser=([^\\=]{1,2000}?\\)?({user}.+?)\s[^\s]{1,2000}?=""",
      """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\snitroDestination_Filename=({malware_url}.+?\\+({malware_file_name}[^\\]{1,2000}?))\s[^\s]{1,2000}?="""
    ]
    SOAR {
      IncidentType = "malware"
      DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "src_host->malwareVictimHost", "malware_url->malwareAttackerUrl", "alert_type->malwareCategory", "malware_file_name->malwareAttackerFile", "dest_ip->malwareAttackerIp"]
      NameTemplate = """McAfee EPO Alert ${alert_name} found"""
      ProjectName = "SOC"
      EntityFields = [
        {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```
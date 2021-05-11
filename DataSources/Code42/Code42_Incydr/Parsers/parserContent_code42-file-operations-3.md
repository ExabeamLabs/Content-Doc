#### Parser Content
```Java
{
Name = code42-file-operations-3
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions= [ """KAFKA_CONNECT_SYSLOG: Code42LogCollector,""""]
  Fields = [
    """KAFKA_CONNECT_SYSLOG: Code42LogCollector,.*?,.*?,(|({accesses}[^,]+)),({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ),.*?,(|({file_path}[^,]+)),(|({file_name}[^,]+)),(|({file_type}[^,]+)),(|({file_category}[^,]+)),(|({bytes}\d{1,100})),(|({file_owner}[^,]+)),(|({md5}[^,]+)),(|({sha256}[^,]+)),(|({time_created}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)),(|({time_modified}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)),(|({user_email}[^,]+)),(|({device_id}[^,]+)),(|({uid}[^,]+)),(|({host}[^,]+)),(|({domain}[^,]+)),(|({src_ip}[^,]+)),(|({private_ip}[^,]+)),(|({actor}[^,]+)),(|({directory}[^,]+)),(|({log_source}[^,]+)),(|({url}[^,]+)),(|({shared}[^,]+)),(|({shared_with}[^,]+)|"({=shared_with}[^"]+))",(|({file_exposure_changed_to}[^,]+)),(|({cloud_drive_id}[^,]+)),(|({detection_source_alias}[^,]+)),(|({file_id}[^,]+)),(|({exposure_type}[^,]+)),(|({process_owner}[^,]+)),(|({process}[^,]+)),(|({tab_title}[^,]+)),,(|({tab_url}[^,]+)),(|({removable_media_vendor}[^,]+)),(|({removable_media_name}[^,]+)),(|({removable_media_serial_number}[^,]+)),(|({removable_media_capacity}[^,]+)),(|({removable_media_bus_type}[^,]+)),(|({removable_media_media_name}[^,]+)),(|({removable_media_volume_name}[^,]+)),(|({removable_media_partition_id}[^,]+)),(|({sync_destination}[^,]+)),(|({email_dlp_policy_names}[^,]+)),(|({subject}[^,]+)),(|({sender}[^,]+)),(|({email_dlp_from}[^,]+))"""
]
  DupFields = ["file_path->file_parent"]
}
```
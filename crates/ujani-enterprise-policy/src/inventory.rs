//! Privacy-conscious, read-only device inventory contracts.
//! This module does not probe endpoints, enroll devices, or authenticate agents.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePowerState {
    Running,
    Sleeping,
    PoweredOff,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryTrust {
    Unverified,
    Enrolled,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInventoryRecord {
    pub device_id: String,
    pub display_name: String,
    pub platform: String,
    pub platform_version: String,
    pub cpu_logical_cores: Option<u16>,
    pub memory_total_mb: Option<u64>,
    pub gpu_summary: Option<String>,
    pub npu_summary: Option<String>,
    pub power_state: DevicePowerState,
    pub trust: InventoryTrust,
    pub owner_opted_in: bool,
    pub admin_approved: bool,
    pub last_seen_unix_ms: u64,
    pub telemetry_source: String,
    pub telemetry_collected_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryError {
    InvalidIdentity,
    MissingPlatform,
    InvalidCpuCount,
    InvalidMemory,
    MissingTelemetryProvenance,
    StaleTelemetry,
    RevokedDevice,
    NotEnrolled,
    NoConsent,
    NotRunning,
}

pub fn validate_inventory_record(
    record: &DeviceInventoryRecord,
    now_unix_ms: u64,
    max_age_ms: u64,
) -> Result<(), InventoryError> {
    if record.device_id.trim().is_empty()
        || record.device_id.len() > 128
        || !record
            .device_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c))
    {
        return Err(InventoryError::InvalidIdentity);
    }
    if record.platform.trim().is_empty() {
        return Err(InventoryError::MissingPlatform);
    }
    if record.cpu_logical_cores == Some(0) {
        return Err(InventoryError::InvalidCpuCount);
    }
    if record.memory_total_mb == Some(0) {
        return Err(InventoryError::InvalidMemory);
    }
    if record.telemetry_source.trim().is_empty()
        || record.telemetry_collected_unix_ms == 0
        || record.last_seen_unix_ms == 0
    {
        return Err(InventoryError::MissingTelemetryProvenance);
    }
    if now_unix_ms < record.telemetry_collected_unix_ms
        || now_unix_ms - record.telemetry_collected_unix_ms > max_age_ms
    {
        return Err(InventoryError::StaleTelemetry);
    }
    if record.trust == InventoryTrust::Revoked {
        return Err(InventoryError::RevokedDevice);
    }
    if record.trust != InventoryTrust::Enrolled {
        return Err(InventoryError::NotEnrolled);
    }
    if !record.owner_opted_in || !record.admin_approved {
        return Err(InventoryError::NoConsent);
    }
    if record.power_state != DevicePowerState::Running {
        return Err(InventoryError::NotRunning);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventorySummary {
    pub total_records: usize,
    pub enrolled: usize,
    pub revoked: usize,
    pub running: usize,
    pub sleeping_or_off: usize,
    pub consented: usize,
    pub stale_or_invalid: usize,
}

pub fn summarize_inventory(
    records: &[DeviceInventoryRecord],
    now_unix_ms: u64,
    max_age_ms: u64,
) -> InventorySummary {
    let mut summary = InventorySummary {
        total_records: records.len(),
        enrolled: 0,
        revoked: 0,
        running: 0,
        sleeping_or_off: 0,
        consented: 0,
        stale_or_invalid: 0,
    };
    for record in records {
        if record.trust == InventoryTrust::Enrolled {
            summary.enrolled += 1;
        }
        if record.trust == InventoryTrust::Revoked {
            summary.revoked += 1;
        }
        if record.power_state == DevicePowerState::Running {
            summary.running += 1;
        } else {
            summary.sleeping_or_off += 1;
        }
        if record.owner_opted_in && record.admin_approved {
            summary.consented += 1;
        }
        if validate_inventory_record(record, now_unix_ms, max_age_ms).is_err() {
            summary.stale_or_invalid += 1;
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> DeviceInventoryRecord {
        DeviceInventoryRecord {
            device_id: "lab-pc-01".into(),
            display_name: "Lab workstation".into(),
            platform: "linux".into(),
            platform_version: "test".into(),
            cpu_logical_cores: Some(8),
            memory_total_mb: Some(16384),
            gpu_summary: Some("test GPU".into()),
            npu_summary: None,
            power_state: DevicePowerState::Running,
            trust: InventoryTrust::Enrolled,
            owner_opted_in: true,
            admin_approved: true,
            last_seen_unix_ms: 100,
            telemetry_source: "agent-v1".into(),
            telemetry_collected_unix_ms: 100,
        }
    }

    #[test]
    fn valid_consented_running_device_passes() {
        assert_eq!(validate_inventory_record(&record(), 110, 1000), Ok(()));
    }

    #[test]
    fn sleeping_device_is_inventory_only_not_schedulable() {
        let mut device = record();
        device.power_state = DevicePowerState::Sleeping;
        assert_eq!(
            validate_inventory_record(&device, 110, 1000),
            Err(InventoryError::NotRunning)
        );
    }

    #[test]
    fn revoked_or_unenrolled_devices_fail_closed() {
        let mut device = record();
        device.trust = InventoryTrust::Revoked;
        assert_eq!(
            validate_inventory_record(&device, 110, 1000),
            Err(InventoryError::RevokedDevice)
        );

        let mut device = record();
        device.trust = InventoryTrust::Unverified;
        assert_eq!(
            validate_inventory_record(&device, 110, 1000),
            Err(InventoryError::NotEnrolled)
        );
    }

    #[test]
    fn consent_is_required() {
        let mut device = record();
        device.owner_opted_in = false;
        assert_eq!(
            validate_inventory_record(&device, 110, 1000),
            Err(InventoryError::NoConsent)
        );
    }

    #[test]
    fn stale_telemetry_fails_closed() {
        assert_eq!(
            validate_inventory_record(&record(), 5000, 100),
            Err(InventoryError::StaleTelemetry)
        );
    }

    #[test]
    fn inventory_summary_does_not_count_sleeping_as_schedulable() {
        let mut device = record();
        device.power_state = DevicePowerState::PoweredOff;
        let summary = summarize_inventory(&[device], 110, 1000);
        assert_eq!(summary.sleeping_or_off, 1);
        assert_eq!(summary.stale_or_invalid, 1);
    }
}

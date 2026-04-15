/*
 * Default Recon-Net YARA Rules
 */

rule Default_Test_Rule {
    meta:
        description = "Default test rule"
        severity = "Low"
    condition:
        filesize > 0
}
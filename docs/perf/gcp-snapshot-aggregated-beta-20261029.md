# GCP snapshot aggregate route, 2026-10-29

The saved GCP scan `52588fc3` recorded `snapshot` as UNKNOWN after HTTP 404 on `GET /compute/v1/projects/{project}/aggregated/snapshots`. [Google's Compute API](https://docs.cloud.google.com/compute/docs/reference/rest/beta/snapshots/aggregatedList) defines the cross-region aggregated snapshot read under `compute/beta`; the v1 snapshot list is global only.

The collector now uses beta only for the aggregated snapshot list. It keeps `returnPartialSuccess`, pagination, the aggregate response shape, and the existing per-resource processing. A snapshot's exact `selfLink` may use v1 or beta; the IAM join accepts either only after matching the project, location, name and region. [Compute beta](https://docs.cloud.google.com/compute/docs/reference/rest/beta) also defines snapshot `getIamPolicy`. Other Compute inventory routes stay on v1.

A one-call read-only request with the retained test credential returned HTTP success and 176 aggregate groups with zero snapshots, versus the saved v1 404. The focused fake-response test keeps one global and one regional snapshot from the same beta response and joins their exact IAM policy reads. This is a route correction, not a complete GCP coverage or production timing claim. No cloud mutation, model call or AWS IAM Access Analyzer operation was made.

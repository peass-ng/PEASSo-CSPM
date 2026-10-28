# Azure Compute Gallery child inventory source proof (2026-10-28)

The collector uses read-only, paged ARM LIST operations through the existing per-scan reader:

- [Gallery Images - List By Gallery](https://learn.microsoft.com/en-us/rest/api/compute/gallery-images/list-by-gallery?view=rest-compute-2026-04-01): `GET {galleryId}/images?api-version=2025-12-03`.
- [Gallery Image Versions - List By Gallery Image](https://learn.microsoft.com/en-us/rest/api/compute/gallery-image-versions/list-by-gallery-image?view=rest-compute-2026-04-01): `GET {imageId}/versions?api-version=2025-12-03`.

Both docs currently identify 2025-12-03 as their supported operation version and specify `nextLink` pagination. The collector validates exact parent-child ARM IDs and native types, stores only image/version identity plus version publication metadata, and retains partial/denied read status. It does not infer that a sharing-capable gallery has a published version from policy alone.

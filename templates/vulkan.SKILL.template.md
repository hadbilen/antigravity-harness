---
name: vulkan
description: >-
  Project-local Vulkan 1.3/1.4 graphics and compute verification discipline: dynamic rendering, synchronization2,
  source-grounded vk.xml/header checks, and deterministic spirv-val + Khronos Validation + headless Lavapipe gates.
  Copy to .agents/skills/vulkan/SKILL.md inside Vulkan repositories. Not for WebGL/WebGPU/Canvas browser games
  (use 'game-engineering') or general non-Vulkan Rust ownership refactoring (use 'rust-harden').
---

# Vulkan Engineering & Three-Stage Verification Protocol

Copy this portable template to `.agents/skills/vulkan/SKILL.md` in repositories that author Vulkan graphics or compute pipelines (C, C++, or Rust via `ash`/`vulkano`/`wgpu-hal`). Keep `templates/vulkan.SKILL.template.md` opt-in so non-graphics repositories incur zero global prompt overhead.

Activate this skill whenever modifying Vulkan instance/device initialization, swapchain lifecycles, pipeline or descriptor layouts, synchronization barriers, GPU memory allocation, or GLSL/HLSL/Slang/WGSL shaders compiled to SPIR-V (`"Vulkan"`, `"vkCmd"`, `"SPIR-V"`, `"swapchain"`, `"dynamic rendering"`, `"synchronization2"`).

## 1. Stage 1: Modern Vulkan `1.3`/`1.4` Baseline Defaults

Target core Vulkan `1.3` (or `1.4` when both loader and physical device expose it) by default, falling back to `1.2 + KHR` extensions (`VK_KHR_dynamic_rendering`, `VK_KHR_synchronization2`), `VK_KHR_portability_enumeration` (MoltenVK), or legacy `1.0`/`1.1` paths only when `ARCHITECTURE.md` or `docs/adr/` explicitly mandates older hardware or portability targets:

* **Dynamic Rendering Over Legacy Render Passes:** Use `VK_KHR_dynamic_rendering` (core in `1.3`: `vkCmdBeginRendering` / `vkCmdEndRendering`, `VkPipelineRenderingCreateInfo`) instead of constructing `VkRenderPass` and `VkFramebuffer` object matrices for standard passes.
* **Synchronization2 Over Legacy Barriers:** Use `VK_KHR_synchronization2` (core in `1.3`: `vkCmdPipelineBarrier2`, `VkImageMemoryBarrier2`, `VkBufferMemoryBarrier2`, `VkMemoryBarrier2`) with minimal, exact `VK_PIPELINE_STAGE_2_*` and `VK_ACCESS_2_*` masks. Reject catch-all `VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT` / `VK_ACCESS_2_MEMORY_WRITE_BIT` masks outside explicit diagnostic probes.
* **Timeline Semaphores & WSI Isolation:** Use `VK_SEMAPHORE_TYPE_TIMELINE` (core in `1.2+`) for frame-in-flight pacing and cross-queue dependencies. Reserve binary semaphores strictly for Window System Integration (`WSI`) handshakes: index image-acquire semaphores per frame-in-flight, and index **render-finished present semaphores strictly per acquired swapchain image** so reused frames cannot trip `VUID-vkQueueSubmit-pSignalSemaphores-00067`.
* **Modern Resource Binding & Memory:** Prefer `VK_KHR_buffer_device_address` (core in `1.2+`) and descriptor indexing (`VK_EXT_descriptor_indexing`, core in `1.2+`, or `VK_EXT_descriptor_buffer` where supported) over per-draw descriptor set thrashing. Manage GPU allocations through a vetted allocator (`VMA` / `gpu-allocator`) respecting `maxMemoryAllocationCount` and alignment limits.
* **Swapchain, Device Loss & Teardown Contracts:** Handle `VK_SUBOPTIMAL_KHR`, `VK_ERROR_OUT_OF_DATE_KHR`, `VK_ERROR_SURFACE_LOST_KHR` (recreate surface and swapchain), `VK_ERROR_DEVICE_LOST` (fail cleanly without infinite timeline waits), and zero-extent minimized windows explicitly on acquire/present paths. Enforce deterministic, null-safe reverse-order destruction (including partial-initialization cleanup): synchronize via `vkDeviceWaitIdle` (or bounded timeline wait, handling `DEVICE_LOST` without panicking) and destroy pipelines, descriptor pools, image views, buffers/images, allocator, swapchain, command pools, sync objects, logical device, surface (before the OS window handle), debug messenger, and instance in strict reverse dependency order.

## 2. Stage 2: Source-Grounded API & Header Verification (`$VULKAN_SDK` / `vk.xml`)

Never invent Vulkan struct members, `sType` tags, `pNext` chain orderings, format feature flags, or wrapper crate method signatures from training memory (`skills/harness/SKILL.md` §2):

1. **Inspect Installed Headers and Registry First:** Before using an extension, struct, or feature bit that is not already exercised in the repository, verify the exact definition against local source:
   * C/C++ headers: `$VULKAN_SDK/include/vulkan/vulkan_core.h` (or `/usr/include/vulkan/vulkan_core.h`).
   * Authoritative XML registry: `$VULKAN_SDK/share/vulkan/registry/vk.xml` (or `/usr/share/vulkan/registry/vk.xml`) for exact `validextensionstructs`, `api="vulkan"`, required promoted core version, and feature struct chains.
   * Rust / language wrappers: inspect the pinned dependency version in `Cargo.lock` and its actual crate source/docs directly, verifying API signatures across major releases (e.g., `ash` `0.37` vs. `0.38`) without guessing.
   * Fallback when `$VULKAN_SDK` and system `/usr/{include,share}/vulkan/` files are absent: verify against the pinned wrapper crate bindings locally or dispatch the read-only `research` subagent against the exact pinned `KhronosGroup/Vulkan-Docs` tag, and declare local `vk.xml` verification skipped under `Not verified` (`GEMINI.md` Rule 8).
2. **Runtime Capability Query Before Enablement:** Query `vkEnumerateInstanceVersion` (loader), `vkGetPhysicalDeviceProperties` (`apiVersion` on the selected physical device), `vkEnumerateDeviceExtensionProperties`, and `vkGetPhysicalDeviceFeatures2` before adding features or extensions to `VkDeviceCreateInfo`. Verify `physicalDeviceProperties.apiVersion >= VK_API_VERSION_1_3` (and `>= VK_API_VERSION_1_4` before chaining `VkPhysicalDeviceVulkan14Features`, falling back to `1.3` or `1.2 + KHR` when older) instead of chaining unsupported version structs. Fail closed with a clear diagnostic naming the missing feature or extension instead of passing unqueried feature bits to the driver.
3. **Explicit Struct Initialization:** Zero-initialize every Vulkan descriptor struct and set `sType` explicitly (`VK_STRUCTURE_TYPE_*`). In Rust, rely on builder/default helpers (`::default()` in `ash`) and never leave uninitialized padding or dangling `pNext` stack pointers across function returns.

## 3. Stage 3: Deterministic Validation & Headless Execution Gate

A Vulkan change is never complete based on compilation alone. Execute all three checks below. When shader, pipeline, or synchronization edits have `0` `spirv-val` or validation-layer runs because required local tooling is absent, declare the gap and halt in `BLOCKED` status (`GEMINI.md` Rule 8); reserve `Not verified` for hardware-only GPU/WSI behaviors when software validation passed:

1. **Shader Compilation & SPIR-V Validation (`spirv-val`):**
   Compile every modified GLSL, HLSL, Slang, or WGSL shader and validate the emitted binary against the target Vulkan environment (`0` errors required):
   ```bash
   glslc --target-env=vulkan1.3 {{shaders/pass.frag}} -o {{build/pass.frag.spv}}
   spirv-val --target-env vulkan1.3 {{build/pass.frag.spv}}
   ```
2. **Khronos Validation & Synchronization Validation (`VK_LAYER_KHRONOS_validation`):**
   Execute render/compute smoke tests with Khronos Validation Layers and Synchronization Validation active. Because environment variables alone only log validation diagnostics without changing process exit status, install a `VK_EXT_debug_utils` callback in the test harness that fails or aborts on `VK_DEBUG_UTILS_MESSAGE_SEVERITY_ERROR_BIT_EXT` (or wrap execution so any `VUID-` / `SYNC-` log line fails the run with exit code `1`):
   ```bash
   VK_INSTANCE_LAYERS=VK_LAYER_KHRONOS_validation \
   VK_KHRONOS_VALIDATION_VALIDATE_SYNC=true \
   VK_KHRONOS_VALIDATION_REPORT_FLAGS=error,warn \
   {{./build/vulkan_smoke_test}}
   ```
   Require `0` `VUID-*` validation errors, `0` `SYNC-*` hazard reports, and `0` leaked Vulkan object handles at `vkDestroyDevice` / `vkDestroyInstance`.
3. **Headless Software ICD Gate (`Lavapipe` / `SwiftShader`):**
   When running in headless CI, containers, or developer terminals without a physical display/GPU, resolve the host's Mesa Lavapipe (`lvp_icd.<arch>.json`) or SwiftShader ICD path dynamically (setting `VK_DRIVER_FILES` on Vulkan loaders `>= 1.3.234` and `VK_ICD_FILENAMES` on older loaders) so pipeline creation, barrier sequencing, shader execution, and buffer/image readback run deterministically across Linux (`x86_64`/`aarch64`), macOS, and Windows:
   ```bash
   LVP_ICD="$(ls /usr/share/vulkan/icd.d/lvp_icd.*.json /usr/local/share/vulkan/icd.d/lvp_icd.*.json 2>/dev/null | head -n 1)"
   VK_DRIVER_FILES="$LVP_ICD" VK_ICD_FILENAMES="$LVP_ICD" \
   VK_INSTANCE_LAYERS=VK_LAYER_KHRONOS_validation \
   VK_KHRONOS_VALIDATION_VALIDATE_SYNC=true \
   {{cargo test --test headless_render_test}}
   ```
   Verify deterministic readback assertions (expected pixel/buffer values, non-NaN outputs, bounded memory usage) alongside zero validation errors. Hardware-only behaviors (physical GPU frame pacing, vendor ray-tracing extensions, real-monitor WSI `MAILBOX`/`FIFO` presentation) must be listed under `Not verified` whenever tested only on Lavapipe.

## 4. Integration With Core Harness Skills

* **Rust Vulkan Projects:** Co-load `skills/rust-harden/SKILL.md` and `skills/rust-harden/references/game-and-realtime.md` (frame-loop zero-allocation discipline, reverse-order GPU `Drop` ordering, swapchain `Outdated`/`Lost` resilience, and `unsafe` narrowing) to keep `unsafe` FFI calls isolated inside small RAII wrappers with explicit `// SAFETY:` proofs.
* **Real-Time Game Loops:** Co-load `skills/game-engineering/SKILL.md` (`Profile B`) to decouple fixed-timestep simulation (`stepTick`) from Vulkan frame presentation and keep per-frame allocations at zero.
* **GPU Performance Profiling:** Hand off to `skills/sweetspot/SKILL.md` only after Stage 3 passes with `0` validation and synchronization errors; never optimize unvalidated pipelines.

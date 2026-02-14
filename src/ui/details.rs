use crate::app::DetailsTab;
use crate::app::LogAtlasApp;
use eframe::egui;

pub fn details_panel(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    ui.heading("Inspector");
    ui.add_space(6.0);

    crate::ui::timeline_bar(ui, app);
    ui.add_space(10.0);

    header(ui, app);
    tab_bar(ui, app);
    ui.separator();
    ui.add_space(8.0);

    match app.ui.details_tab {
        DetailsTab::Event => event_details(ui, app),
        DetailsTab::Overview => overview(ui, app),
        DetailsTab::Processes => processes(ui, app),
        DetailsTab::Modules => modules(ui, app),
        DetailsTab::Threads => threads(ui, app),
        DetailsTab::Exception => exception(ui, app),
        DetailsTab::Detections => detections(ui, app),
    }
}

fn header(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    if let Some(path) = &app.dump_path {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Minidump").strong());
            ui.monospace(path.display().to_string());
        });
    }
}

fn tab_bar(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    ui.horizontal(|ui| {
        ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Event, "Event");

        let enabled = app.dump_report.is_some();
        ui.add_enabled_ui(enabled, |ui| {
            ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Overview, "Overview");
            ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Processes, "Processes");
            ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Modules, "Modules");
            ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Threads, "Threads");
            ui.selectable_value(&mut app.ui.details_tab, DetailsTab::Exception, "Exception");
            ui.selectable_value(
                &mut app.ui.details_tab,
                DetailsTab::Detections,
                "Detections",
            );
        });
    });
}

fn event_details(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    ui.label(egui::RichText::new("Event Details").strong());
    ui.add_space(8.0);

    let Some(id) = app.selected else {
        ui.label("Select an event in the timeline.");
        return;
    };

    let Some(ev) = app.events.get(id) else {
        ui.label("Selected event not found.");
        return;
    };

    ui.horizontal(|ui| {
        ui.monospace(format!("+{}ms", ev.t_ms));
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(ev.severity.label())
                .color(crate::ui::severity_color(ev.severity))
                .strong(),
        );
        ui.add_space(10.0);
        ui.label(egui::RichText::new(&ev.title).strong());
    });

    ui.add_space(10.0);
    ui.label(egui::RichText::new("Source").strong());
    ui.monospace(&ev.source);

    ui.add_space(10.0);
    ui.label(egui::RichText::new("Details").strong());
    egui::ScrollArea::vertical()
        .id_source("event_details_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(egui::Label::new(&ev.details).wrap(true));
        });
}

fn overview(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(sum) = &app.dump_summary else {
        ui.label("Load a minidump to see an overview.");
        return;
    };
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to see an overview.");
        return;
    };

    ui.label(egui::RichText::new("File").strong());
    if let Some(sz) = sum.file_size {
        ui.monospace(format!("size={sz} bytes"));
    }
    if let Some(ts) = sum.time_date_stamp {
        ui.monospace(format!("time_date_stamp_unix={ts}"));
        if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(ts as u64) {
            ui.monospace(format!("time_date_stamp_utc={utc}"));
        }
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("System").strong());
    if let Some(os) = &report.os {
        ui.monospace(format!("os={os}"));
    }
    if let Some(cpu) = &report.cpu {
        ui.monospace(format!("cpu={cpu}"));
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Process").strong());
    if let Some(p) = &report.process {
        if let Some(img) = &p.main_image {
            ui.monospace(format!("image={img}"));
        }
        if let Some(v) = &p.main_image_version {
            ui.monospace(format!("version={v}"));
        }
        if let Some(pid) = p.pid {
            ui.monospace(format!("pid={pid}"));
        }
        if let Some(t) = p.create_time_unix {
            ui.monospace(format!("create_time_unix={t}"));
            if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(t) {
                ui.monospace(format!("create_time_utc={utc}"));
            }
        }
        if let Some(il) = p.integrity_level {
            ui.monospace(format!("integrity_level={il}"));
        }
        if let Some(f) = p.execute_flags {
            ui.monospace(format!("execute_flags=0x{f:08X}"));
        }
        if let Some(pp) = p.protected_process {
            ui.monospace(format!("protected_process={pp}"));
        }
    } else {
        ui.label("No MiscInfo stream (process fields unavailable).");
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Streams").strong());
    ui.monospace(format!("modules={}", report.modules.len()));
    ui.monospace(format!("threads={}", report.threads.len()));
    if let Some(n) = report.memory_region_count {
        ui.monospace(format!("memory_regions={n}"));
    }
    if let Some(n) = report.memory_region_64_count {
        ui.monospace(format!("memory64_regions={n}"));
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Thread Timing").strong());
    if let Some(last) = report.last_thread_create_time_unix() {
        ui.monospace(format!("last_thread_create_time_unix={last}"));
        if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(last) {
            ui.monospace(format!("last_thread_create_time_utc={utc}"));
        }
    } else {
        ui.label("No thread creation timestamps available (ThreadInfoList stream missing).");
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Exec Artifacts").strong());
    if report.exec_artifacts.is_empty() {
        ui.label("None recovered (best-effort scan).");
    } else {
        ui.label(format!(
            "Recovered {} potential command-line artifacts (see Processes tab).",
            report.exec_artifacts.len()
        ));
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Exception").strong());
    if let Some(exc) = &report.exception {
        ui.monospace(format!("thread_id=0x{:X}", exc.thread_id));
        ui.monospace(format!("code=0x{:08X}", exc.code));
        ui.monospace(format!("address=0x{:016X}", exc.address));
        ui.monospace(format!("flags=0x{:08X} params={}", exc.flags, exc.number_parameters));
    } else {
        ui.label("No exception stream present.");
    }
}

fn processes(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to inspect process details.");
        return;
    };

    ui.push_id("processes_tab", |ui| {
    ui.label(egui::RichText::new("Process").strong());
    if let Some(p) = &report.process {
        if let Some(img) = &p.main_image {
            ui.monospace(format!("image={img}"));
        }
        if let Some(v) = &p.main_image_version {
            ui.monospace(format!("version={v}"));
        }
        if let Some(pid) = p.pid {
            ui.monospace(format!("pid={pid}"));
        }
        if let Some(t) = p.create_time_unix {
            ui.monospace(format!("create_time_unix={t}"));
            if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(t) {
                ui.monospace(format!("create_time_utc={utc}"));
            }
        }
        if let Some(il) = p.integrity_level {
            ui.monospace(format!("integrity_level={il}"));
        }
        if let Some(f) = p.execute_flags {
            ui.monospace(format!("execute_flags=0x{f:08X}"));
        }
        if let Some(pp) = p.protected_process {
            ui.monospace(format!("protected_process={pp}"));
        }
    } else {
        ui.label("No MiscInfo stream (process fields unavailable).");
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Recovered Exec Artifacts").strong());
    ui.label("Best-effort scan of dump memory for command-line like strings (not guaranteed).");

    ui.add_space(10.0);
    ui.label(egui::RichText::new("Thread Timing").strong());
    if let Some(last) = report.last_thread_create_time_unix() {
        ui.monospace(format!("last_thread_create_time_unix={last}"));
        if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(last) {
            ui.monospace(format!("last_thread_create_time_utc={utc}"));
        }
    } else {
        ui.label("No thread creation timestamps available (ThreadInfoList stream missing).");
    }

    ui.add_space(12.0);
    ui.label(egui::RichText::new("Injected / Exec Memory").strong());
    ui.label("Best-effort: committed private executable allocations not backed by modules.");
    if report.injected_regions.is_empty() {
        ui.label("None detected (or MemoryInfoList stream missing).");
    } else {
        egui::ScrollArea::vertical()
            .id_source("injected_regions_scroll")
            .max_height(220.0)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (idx, r) in report.injected_regions.iter().enumerate() {
                    ui.push_id(idx, |ui| {
                        let selected = app.ui.selected_injected_region == Some(idx);

                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(selected, format!("#{idx}"))
                                .clicked()
                            {
                                app.ui.selected_injected_region = Some(idx);
                            }

                            ui.label(
                                egui::RichText::new(r.risk.label())
                                    .color(crate::ui::severity_color(r.risk))
                                    .strong(),
                            );
                            ui.monospace(format!("base=0x{:016X}", r.base));
                            if r.size != 0 {
                                ui.monospace(format!("size=0x{:X}", r.size));
                            }
                            ui.monospace(format!("prot={}", r.protection));
                        });

                        if !r.reasons.is_empty() {
                            ui.add_space(2.0);
                            ui.add(egui::Label::new(r.reasons.join("; ")).wrap(true));
                        }

                        ui.add_space(6.0);
                        ui.separator();
                        ui.add_space(6.0);
                    });
                }
            });

        if let Some(idx) = app.ui.selected_injected_region {
            if let Some(r) = report.injected_regions.get(idx) {
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(egui::RichText::new("Selected Allocation").strong());
                ui.monospace(format!("base=0x{:016X} size=0x{:X}", r.base, r.size));
                ui.monospace(format!("protection={}", r.protection));
                ui.monospace(format!("type={}", r.ty));
                ui.monospace(format!("state={}", r.state));
                if !r.reasons.is_empty() {
                    ui.add_space(6.0);
                    for reason in &r.reasons {
                        ui.add(egui::Label::new(format!("- {reason}")).wrap(true));
                    }
                }
            }
        }
    }

    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut app.ui.process_filter);
        if ui.button("Clear##process_filter").clicked() {
            app.ui.process_filter.clear();
        }
    });

    let filter = app.ui.process_filter.trim().to_ascii_lowercase();

    egui::ScrollArea::vertical()
        .id_source("exec_artifacts_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, a) in report.exec_artifacts.iter().enumerate() {
                if !filter.is_empty()
                    && !a.image.to_ascii_lowercase().contains(&filter)
                    && !a.command_line.to_ascii_lowercase().contains(&filter)
                {
                    continue;
                }

                ui.push_id(idx, |ui| {
                    let selected = app.ui.selected_exec_artifact == Some(idx);

                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(selected, format!("#{idx}"))
                            .clicked()
                        {
                            app.ui.selected_exec_artifact = Some(idx);
                        }
                        ui.monospace(match a.encoding {
                            crate::model::ExecArtifactEncoding::Ascii => "ascii",
                            crate::model::ExecArtifactEncoding::Utf16Le => "utf16le",
                        });
                        ui.monospace(&a.image);
                        if let Some(addr) = a.address {
                            ui.monospace(format!("addr=0x{addr:016X}"));
                        }
                    });
                    ui.add_space(2.0);
                    ui.add(egui::Label::new(&a.command_line).wrap(true));

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);
                });
            }
        });

    if let Some(idx) = app.ui.selected_exec_artifact {
        if let Some(a) = report.exec_artifacts.get(idx) {
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Selected Artifact").strong());
            ui.monospace(format!("image={}", a.image));
            if let Some(addr) = a.address {
                ui.monospace(format!("address=0x{addr:016X}"));
            }
            ui.add_space(6.0);
            egui::ScrollArea::vertical()
                .id_source("selected_artifact_scroll")
                .max_height(140.0)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(egui::Label::new(&a.command_line).wrap(true));
                });
        }
    }
    });
}

fn modules(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to browse modules.");
        return;
    };

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut app.ui.module_filter);
        if ui.button("Clear##module_filter").clicked() {
            app.ui.module_filter.clear();
        }
    });
    ui.add_space(6.0);

    let filter = app.ui.module_filter.trim().to_ascii_lowercase();

    egui::ScrollArea::vertical()
        .id_source("modules_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("modules_grid")
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("#").strong());
                    ui.label(egui::RichText::new("Base").strong());
                    ui.label(egui::RichText::new("Size").strong());
                    ui.label(egui::RichText::new("TimeDateStamp").strong());
                    ui.label(egui::RichText::new("Version").strong());
                    ui.label(egui::RichText::new("Name").strong());
                    ui.end_row();

                    for (idx, m) in report.modules.iter().enumerate() {
                        if !filter.is_empty()
                            && !m.name.to_ascii_lowercase().contains(&filter)
                            && !format!("{:016X}", m.base)
                                .to_ascii_lowercase()
                                .contains(&filter)
                        {
                            continue;
                        }

                        let selected = app.ui.selected_module == Some(idx);
                        if ui.selectable_label(selected, idx.to_string()).clicked() {
                            app.ui.selected_module = Some(idx);
                        }
                        ui.monospace(format!("0x{:016X}", m.base));
                        ui.monospace(format!("0x{:X}", m.size));
                        ui.monospace(format!("0x{:08X}", m.time_date_stamp));
                        ui.monospace(m.file_version.as_deref().unwrap_or("-"));
                        ui.label(&m.name);
                        ui.end_row();
                    }
                });
        });

    if let Some(idx) = app.ui.selected_module {
        if let Some(m) = report.modules.get(idx) {
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Selected Module").strong());
            ui.monospace(&m.name);
            ui.monospace(format!("base=0x{:016X} size=0x{:X}", m.base, m.size));
            ui.monospace(format!(
                "checksum=0x{:08X} timestamp=0x{:08X}",
                m.checksum, m.time_date_stamp
            ));
        }
    }
}

fn threads(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to browse threads.");
        return;
    };

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut app.ui.thread_filter);
        if ui.button("Clear##thread_filter").clicked() {
            app.ui.thread_filter.clear();
        }
    });
    ui.add_space(6.0);

    let filter = app.ui.thread_filter.trim().to_ascii_lowercase();

    egui::ScrollArea::vertical()
        .id_source("threads_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("threads_grid")
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("TID").strong());
                    ui.label(egui::RichText::new("Name").strong());
                    ui.label(egui::RichText::new("Created(UTC)").strong());
                    ui.label(egui::RichText::new("TEB").strong());
                    ui.label(egui::RichText::new("StackStart").strong());
                    ui.label(egui::RichText::new("StackSize").strong());
                    ui.end_row();

                    for t in &report.threads {
                        let name = t.name.as_deref().unwrap_or("-");
                        if !filter.is_empty()
                            && !format!("{}", t.thread_id)
                                .to_ascii_lowercase()
                                .contains(&filter)
                            && !name.to_ascii_lowercase().contains(&filter)
                        {
                            continue;
                        }

                        let selected = app.ui.selected_thread == Some(t.thread_id);
                        if ui
                            .selectable_label(selected, format!("0x{:X}", t.thread_id))
                            .clicked()
                        {
                            app.ui.selected_thread = Some(t.thread_id);
                        }
                        ui.label(name);
                        ui.monospace(
                            t.create_time_unix
                                .and_then(crate::util::time::unix_seconds_to_utc_string)
                                .unwrap_or_else(|| "-".into()),
                        );
                        ui.monospace(format!("0x{:016X}", t.teb));
                        ui.monospace(format!("0x{:016X}", t.stack_start));
                        ui.monospace(format!("0x{:X}", t.stack_size));
                        ui.end_row();
                    }
                });
        });

    if let Some(tid) = app.ui.selected_thread {
        if let Some(t) = report.threads.iter().find(|t| t.thread_id == tid) {
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(10.0);
            ui.label(egui::RichText::new("Selected Thread").strong());
            ui.monospace(format!("thread_id=0x{tid:X}"));
            if let Some(name) = &t.name {
                ui.monospace(format!("name={name}"));
            }
            if let Some(ft) = t.create_time_filetime {
                ui.monospace(format!("create_time_filetime={ft}"));
            }
            if let Some(unix) = t.create_time_unix {
                ui.monospace(format!("create_time_unix={unix}"));
                if let Some(utc) = crate::util::time::unix_seconds_to_utc_string(unix) {
                    ui.monospace(format!("create_time_utc={utc}"));
                }
            }
            if let Some(start) = t.start_address {
                ui.monospace(format!("start_address=0x{start:016X}"));
            }
            ui.monospace(format!(
                "suspend_count={} priority_class=0x{:X} priority=0x{:X}",
                t.suspend_count, t.priority_class, t.priority
            ));
            ui.monospace(format!(
                "teb=0x{:016X} stack_start=0x{:016X} stack_size=0x{:X}",
                t.teb, t.stack_start, t.stack_size
            ));
        }
    }
}

fn exception(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to inspect the exception stream.");
        return;
    };

    let Some(exc) = &report.exception else {
        ui.label("No exception stream present in this minidump.");
        return;
    };

    ui.label(egui::RichText::new("Exception").strong());
    ui.monospace(format!("thread_id=0x{:X}", exc.thread_id));
    ui.monospace(format!("code=0x{:08X}", exc.code));
    ui.monospace(format!("flags=0x{:08X}", exc.flags));
    ui.monospace(format!("address=0x{:016X}", exc.address));
    ui.monospace(format!("number_parameters={}", exc.number_parameters));
}

fn detections(ui: &mut egui::Ui, app: &mut LogAtlasApp) {
    let Some(report) = &app.dump_report else {
        ui.label("Load a minidump to see detections.");
        return;
    };

    let dets = report.detections();
    if dets.is_empty() {
        ui.label("No detections fired (basic rules).");
        return;
    }

    egui::ScrollArea::vertical()
        .id_source("detections_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for det in dets {
                ui.horizontal(|ui| {
                    ui.label(
                        egui::RichText::new(det.severity.label())
                            .color(crate::ui::severity_color(det.severity))
                            .strong(),
                    );
                    ui.label(egui::RichText::new(det.title).strong());
                });
                ui.add(egui::Label::new(det.details).wrap(true));
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
            }
        });
}

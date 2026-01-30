use crate::container;
use crate::fsmeta::NodeType;
use eframe::egui;
use rfd::FileDialog;
use std::path::PathBuf;
use zeroize::Zeroize;

pub fn run() -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 700.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Vault",
        native_options,
        Box::new(|_cc| Box::new(VaultApp::default())),
    )
    .map_err(|e| anyhow::anyhow!("gui: {e}"))?;

    Ok(())
}

#[derive(Default)]
struct VaultApp {
    // locked screen
    vault_path: String,
    password: String,
    create_password: String,
    status: String,

    // session
    sess: Option<container::Session>,
    unlocked_password: String,

    // navigation
    current_dir_id: u64,
    selected_id: Option<u64>,

    // actions
    new_folder_name: String,
    rename_to: String,

    // viewer
    viewer_bytes: Option<Vec<u8>>,
    viewer_mode: ViewerMode,
    viewer_text: String,
    viewer_error: String,
    viewer_texture: Option<egui::TextureHandle>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum ViewerMode {
    #[default]
    None,
    Text,
    Hex,
    Image,
}

impl VaultApp {
    fn lock(&mut self) {
        self.sess = None;
        self.selected_id = None;
        self.current_dir_id = 1;

        self.viewer_bytes = None;
        self.viewer_text.clear();
        self.viewer_error.clear();
        self.viewer_texture = None;
        self.viewer_mode = ViewerMode::None;

        self.unlocked_password.zeroize();
    }

    fn selected_node_name(&self) -> String {
        let Some(sess) = &self.sess else {
            return String::new();
        };
        let Some(id) = self.selected_id else {
            return String::new();
        };
        sess.meta
            .get_node(id)
            .map(|n| n.name.clone())
            .unwrap_or_default()
    }

    fn open_vault_action(&mut self) {
        self.status.clear();
        match container::open_vault(&self.vault_path, &self.password) {
            Ok(sess) => {
                self.current_dir_id = sess.meta.root_id;
                self.selected_id = Some(sess.meta.root_id);
                self.sess = Some(sess);

                self.unlocked_password = self.password.clone();
                self.password.zeroize();
            }
            Err(e) => self.status = format!("Не удалось открыть: {e}"),
        }
    }

    fn create_vault_action(&mut self) {
        self.status.clear();
        if self.vault_path.trim().is_empty() {
            self.status = "Укажите путь к vault.dat".to_string();
            return;
        }
        if self.create_password.is_empty() {
            self.status = "Задайте пароль".to_string();
            return;
        }

        match container::create_vault(&self.vault_path, &self.create_password, 131072, 3) {
            Ok(()) => self.status = "Создано. Теперь нажмите Открыть".to_string(),
            Err(e) => self.status = format!("Не удалось создать: {e}"),
        }
    }

    fn render_dir_tree(&mut self, ui: &mut egui::Ui, parent_id: u64) {
        // Важно: не держим borrow на self.sess во время рекурсивного вызова.
        let dirs: Vec<(u64, String)> = match self.sess.as_ref() {
            Some(sess) => sess
                .meta
                .children_of(parent_id)
                .into_iter()
                .filter(|n| n.node_type == NodeType::Dir)
                .map(|n| (n.id, n.name.clone()))
                .collect(),
            None => return,
        };

        for (dir_id, dir_name) in dirs {
            let label = if self.current_dir_id == dir_id {
                format!("📁 {}", dir_name)
            } else {
                dir_name
            };

            egui::CollapsingHeader::new(label)
                .default_open(false)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Открыть").clicked() {
                            self.current_dir_id = dir_id;
                            self.selected_id = Some(dir_id);
                        }
                    });
                    self.render_dir_tree(ui, dir_id);
                });
        }
    }

    fn load_viewer(&mut self, ctx: &egui::Context) {
        self.viewer_bytes = None;
        self.viewer_text.clear();
        self.viewer_error.clear();
        self.viewer_texture = None;
        self.viewer_mode = ViewerMode::None;

        let Some(sess) = &self.sess else {
            return;
        };
        let Some(id) = self.selected_id else {
            return;
        };
        let Some(node) = sess.meta.get_node(id) else {
            return;
        };
        if node.node_type != NodeType::File {
            return;
        }

        match container::read_file_bytes(sess, id) {
            Ok(bytes) => {
                // Text
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    self.viewer_mode = ViewerMode::Text;
                    self.viewer_text = s.to_string();
                    self.viewer_bytes = Some(bytes);
                    return;
                }

                // Image
                if let Ok(img) = image::load_from_memory(&bytes) {
                    let rgba = img.to_rgba8();
                    let size = [rgba.width() as usize, rgba.height() as usize];
                    let pixels = rgba.into_raw();
                    let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                    self.viewer_texture = Some(ctx.load_texture(
                        "vault_image",
                        color_image,
                        egui::TextureOptions::default(),
                    ));
                    self.viewer_mode = ViewerMode::Image;
                    self.viewer_bytes = Some(bytes);
                    return;
                }

                // Hex fallback
                self.viewer_mode = ViewerMode::Hex;
                self.viewer_bytes = Some(bytes);
                self.viewer_error = "Бинарный файл: показан hex-превью (MVP)".to_string();
            }
            Err(e) => self.viewer_error = format!("Ошибка чтения: {e}"),
        }
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Vault");
                if self.sess.is_some() {
                    if ui.button("Lock").clicked() {
                        self.lock();
                    }
                }
                ui.separator();
                ui.label(&self.status);
            });
        });

        if self.sess.is_none() {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.heading("Открыть / создать контейнер");
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    ui.label("vault.dat:");
                    ui.text_edit_singleline(&mut self.vault_path);
                    if ui.button("Выбрать").clicked() {
                        if let Some(p) = FileDialog::new().add_filter("vault", &["dat"]).pick_file() {
                            self.vault_path = p.display().to_string();
                        }
                    }
                });

                ui.horizontal(|ui| {
                    ui.label("Пароль:");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                    if ui.button("Открыть").clicked() {
                        self.open_vault_action();
                    }
                });

                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Новый пароль:");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.create_password)
                            .password(true)
                            .hint_text("придумайте пароль"),
                    );
                    if ui.button("Создать новый контейнер").clicked() {
                        self.create_vault_action();
                    }
                });

                ui.add_space(12.0);
                ui.label("Примечание: 100% 'без следов' на ПК гарантировать нельзя. В этом GUI нет 'Открыть во внешней программе' — чтобы уменьшить утечки/следы.");
            });
            return;
        }

        egui::SidePanel::left("left").resizable(true).show(ctx, |ui| {
            ui.heading("Папки");
            ui.separator();

            if ui.button("Корень").clicked() {
                if let Some(sess) = &self.sess {
                    self.current_dir_id = sess.meta.root_id;
                    self.selected_id = Some(sess.meta.root_id);
                }
            }

            self.render_dir_tree(ui, 1);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            // Сначала собираем действия (клики) в переменные, а изменения контейнера делаем ПОСЛЕ ui.horizontal.
            let mut do_mkdir: Option<String> = None;
            let mut do_import: Option<PathBuf> = None;
            let mut do_export: bool = false;
            let mut do_delete: bool = false;
            let mut do_view: bool = false;
            let mut do_start_rename: bool = false;
            let mut do_apply_rename: bool = false;

            ui.horizontal(|ui| {
                ui.label(format!("Текущая папка: id={}", self.current_dir_id));

                ui.separator();
                ui.label("Новая папка:");
                ui.text_edit_singleline(&mut self.new_folder_name);
                if ui.button("Создать").clicked() {
                    do_mkdir = Some(self.new_folder_name.trim().to_string());
                }

                ui.separator();

                if ui.button("Импорт файла").clicked() {
                    if let Some(p) = FileDialog::new().pick_file() {
                        do_import = Some(p);
                    }
                }

                if ui.button("Экспорт").clicked() {
                    do_export = true;
                }

                if ui.button("Переименовать").clicked() {
                    do_start_rename = true;
                }

                if ui.button("Удалить").clicked() {
                    do_delete = true;
                }

                if ui.button("Просмотр").clicked() {
                    do_view = true;
                }
            });

            // start rename
            if do_start_rename {
                self.rename_to = self.selected_node_name();
            }

            // rename editor
            if !self.rename_to.is_empty() {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label("Новое имя:");
                    ui.text_edit_singleline(&mut self.rename_to);
                    if ui.button("OK").clicked() {
                        do_apply_rename = true;
                    }
                    if ui.button("Отмена").clicked() {
                        self.rename_to.clear();
                    }
                });
            }

            // Выполняем операции над контейнером здесь (нет borrow-конфликтов с egui).
            if let Some(sess) = self.sess.as_mut() {
                if let Some(name) = do_mkdir {
                    if name.trim().is_empty() {
                        self.status = "Введите имя папки".to_string();
                    } else {
                        match sess.meta.mkdir(self.current_dir_id, name) {
                            Ok(new_id) => {
                                if let Err(e) = container::save_metadata(sess, &self.unlocked_password) {
                                    self.status = format!("save: {e}");
                                } else {
                                    self.new_folder_name.clear();
                                    self.selected_id = Some(new_id);
                                    self.status.clear();
                                }
                            }
                            Err(e) => self.status = format!("mkdir: {e}"),
                        }
                    }
                }

                if let Some(p) = do_import {
                    match container::import_file(sess, &self.unlocked_password, &p, self.current_dir_id, None) {
                        Ok(id) => {
                            self.selected_id = Some(id);
                            self.status.clear();
                        }
                        Err(e) => self.status = format!("import: {e}"),
                    }
                }

                if do_export {
                    if let Some(id) = self.selected_id {
                        if let Some(node) = sess.meta.get_node(id) {
                            if node.node_type != NodeType::File {
                                self.status = "Экспорт только для файлов".to_string();
                            } else if let Some(out) =
                                FileDialog::new().set_file_name(&node.name).save_file()
                            {
                                if let Err(e) = container::export_file(sess, id, &out) {
                                    self.status = format!("export: {e}");
                                } else {
                                    self.status = "Экспортировано".to_string();
                                }
                            }
                        } else {
                            self.status = "Не найдено".to_string();
                        }
                    } else {
                        self.status = "Выберите файл".to_string();
                    }
                }

                if do_delete {
                    if let Some(id) = self.selected_id {
                        match sess.meta.remove_subtree(id) {
                            Ok(()) => match container::save_metadata(sess, &self.unlocked_password) {
                                Ok(()) => {
                                    self.selected_id = None;
                                    self.viewer_mode = ViewerMode::None;
                                    self.viewer_bytes = None;
                                    self.status = "Удалено (MVP: место в контейнере не очищается)".to_string();
                                }
                                Err(e) => self.status = format!("save: {e}"),
                            },
                            Err(e) => self.status = format!("delete: {e}"),
                        }
                    } else {
                        self.status = "Ничего не выбрано".to_string();
                    }
                }

                if do_apply_rename {
                    if let Some(id) = self.selected_id {
                        match sess.meta.rename(id, self.rename_to.trim().to_string()) {
                            Ok(()) => match container::save_metadata(sess, &self.unlocked_password) {
                                Ok(()) => {
                                    self.rename_to.clear();
                                    self.status.clear();
                                }
                                Err(e) => self.status = format!("save: {e}"),
                            },
                            Err(e) => self.status = format!("rename: {e}"),
                        }
                    } else {
                        self.status = "Ничего не выбрано".to_string();
                    }
                }
            }

            if do_view {
                self.load_viewer(ctx);
            }

            ui.separator();
            ui.heading("Содержимое");

            let children = self
                .sess
                .as_ref()
                .map(|s| s.meta.children_of(self.current_dir_id))
                .unwrap_or_default();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for n in children {
                    let label = match n.node_type {
                        NodeType::Dir => format!("[DIR]  {} (id={})", n.name, n.id),
                        NodeType::File => format!("[FILE] {} (id={}, {} bytes)", n.name, n.id, n.size),
                    };
                    let selected = self.selected_id == Some(n.id);
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected_id = Some(n.id);
                        if n.node_type == NodeType::Dir {
                            self.current_dir_id = n.id;
                        }
                    }
                }
            });

            ui.separator();
            ui.heading("Просмотр (внутри приложения)");
            if !self.viewer_error.is_empty() {
                ui.label(&self.viewer_error);
            }

            match self.viewer_mode {
                ViewerMode::None => {
                    ui.label("Выберите файл и нажмите 'Просмотр'.");
                }
                ViewerMode::Text => {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.viewer_text)
                            .desired_rows(14)
                            .code_editor(),
                    );
                }
                ViewerMode::Image => {
                    if let Some(tex) = &self.viewer_texture {
                        let avail = ui.available_size();
                        let mut size = tex.size_vec2();
                        let scale = (avail.x / size.x).min(avail.y / size.y).min(1.0);
                        size *= scale;
                        ui.add(egui::Image::new(tex).fit_to_exact_size(size));
                    } else {
                        ui.label("(не удалось загрузить изображение)");
                    }
                }
                ViewerMode::Hex => {
                    if let Some(bytes) = &self.viewer_bytes {
                        let preview_len = bytes.len().min(4096);
                        let mut s = String::new();
                        for (i, b) in bytes[..preview_len].iter().enumerate() {
                            if i % 16 == 0 {
                                s.push_str(&format!("\n{:08x}: ", i));
                            }
                            s.push_str(&format!("{:02x} ", b));
                        }
                        ui.add(egui::TextEdit::multiline(&mut s).desired_rows(14).code_editor());
                    }
                }
            }
        });
    }
}
#include <gtk/gtk.h>

void on_activate(GtkApplication* app, gpointer user_data) {
    GtkWidget *window;
    GtkWidget *button1;
    GtkWidget *button2;
    GtkWidget *label1;
    GtkWidget *label2;
    GtkWidget *label3;
    GtkWidget *label4;
    GtkWidget *label5;
    GtkWidget *label6;
    GtkWidget *combo_box1;
    GtkWidget *combo_box2;
    GtkWidget *combo_box3;
    GtkWidget *combo_box4;
    GtkWidget *vbox;
    GtkWidget *hbox1;
    GtkWidget *hbox2;
    GtkWidget *hbox3;
    GtkWidget *hbox4;

    window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(window), "Labyrinth");
    gtk_window_set_default_size(GTK_WINDOW(window), 400, 300);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), vbox);

    label1 = gtk_label_new("Select a directory to monitor:");
    gtk_box_pack_start(GTK_BOX(vbox), label1, FALSE, FALSE, 0);

    button1 = gtk_button_new_with_label("Select Directory");
    gtk_box_pack_start(GTK_BOX(vbox), button1, FALSE, FALSE, 0);

    label2 = gtk_label_new("Select a key file:");
    gtk_box_pack_start(GTK_BOX(vbox), label2, FALSE, FALSE, 0);

    button2 = gtk_button_new_with_label("Select Key File");
    gtk_box_pack_start(GTK_BOX(vbox), button2, FALSE, FALSE, 0);

    label3 = gtk_label_new("Select trigger for encryption:");
    gtk_box_pack_start(GTK_BOX(vbox), label3, FALSE, FALSE, 0);

    combo_box1 = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box1), "Create");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box1), "Delete");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box1), "Modify");
    gtk_box_pack_start(GTK_BOX(vbox), combo_box1, FALSE, FALSE, 0);

    label4 = gtk_label_new("Select encryption mode:");
    gtk_box_pack_start(GTK_BOX(vbox), label4, FALSE, FALSE, 0);

    combo_box2 = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box2), "Individual");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box2), "Group");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo_box2), "All");
    gtk_box_pack_start(GTK_BOX(vbox), combo_box2, FALSE, FALSE, 0);

    label5 = gtk_label_new("Encryption Handler Status: Idle");
    gtk_box_pack_start(GTK_BOX(vbox), label5, FALSE, FALSE, 0);

    hbox1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_box_pack_start(GTK_BOX(vbox), hbox1, FALSE, FALSE, 0);

    label6 = gtk_label_new("Created by Blu Corbel");
    gtk_box_pack_start(GTK_BOX(hbox1), label6, FALSE, FALSE, 0);

    gtk_widget_show_all(window);
}

int main(int argc, char **argv) {
    GtkApplication *app;
    int status;

    app = gtk_application_new("com.example.Labyrinth", G_APPLICATION_FLAGS_NONE);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
    status = g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    return status;
}
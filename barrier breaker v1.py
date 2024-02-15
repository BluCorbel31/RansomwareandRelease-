import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import language_tool_python

spell_checker = language_tool_python.LanguageTool('en-US')

def word_count(text):
    # Split the text into words
    words = text.split()
    # Count the number of words
    word_count = len(words)
    return word_count

def highlight_misspelled_words(text):
    # Split the text into words
    words = text.split()
    # Find misspelled words
    misspelled_words = spell_checker.unknown(words)
    # Highlight misspelled words in the text
    highlighted_text = text
    for word in misspelled_words:
        highlighted_text = highlighted_text.replace(word, f'***{word}***')
    return highlighted_text

def correct_punctuation_and_grammar(text, language='en-US'):
    tool = language_tool_python.LanguageTool(language)
    # Auto-correct punctuation and grammar
    matches = tool.check(text)
    corrected_text = language_tool_python.utils.correct(text, matches)
    return corrected_text

def analyze_text(text, language='en-US'):
    # Perform text analysis
    word_count_result = word_count(text)
    corrected_text = correct_punctuation_and_grammar(text, language)
    highlighted_text = highlight_misspelled_words(corrected_text)
    # Return the analysis result
    return {"word_count": word_count_result, "corrected_text": corrected_text, "highlighted_text": highlighted_text}

# Function to retrieve the flag image based on the language
def get_flag_image(language):
    # Dictionary mapping languages to flag file paths
    language_flags = {
        'en-US': 'flags/us_flag.png',
        'fr': 'flags/france_flag.png',
        'es': 'flags/spain_flag.png',
        # Add more languages and flag paths as needed
    }
    # Check if the language is in the dictionary
    if language in language_flags:
        flag_path = language_flags[language]
        return Image.open(flag_path)
    else:
        # If language not found, return a default flag image
        return Image.open('flags/default_flag.png')

# Function to display the flag image in the GUI
def display_flag(language):
    flag_image = get_flag_image(language)
    flag_image = flag_image.resize((200, 100), Image.ANTIALIAS)
    flag_photo = ImageTk.PhotoImage(flag_image)

    # Update flag image on the GUI
    flag_label.config(image=flag_photo)
    flag_label.image = flag_photo

# Function to handle language change event
def change_language(event):
    selected_language = language_combobox.get()
    display_flag(selected_language)
    # Perform text analysis with the new language
    analysis_result = analyze_text(text_to_analyze_str.get(), selected_language)
    corrected_text_label.config(text=analysis_result['corrected_text'])
    word_count_label.config(text=f"Word Count: {analysis_result['word_count']}")
    highlighted_text_label.config(text=analysis_result['highlighted_text'])

# Function to autocorrect all mistakes found in the analysis
def autocorrect_mistakes():
    text = text_to_analyze_str.get()
    corrected_text = correct_punctuation_and_grammar(text)
    text_to_analyze_str.set(corrected_text)
    analysis_result = analyze_text(corrected_text, language_combobox.get())
    corrected_text_label.config(text=analysis_result['corrected_text'])
    highlighted_text_label.config(text=analysis_result['highlighted_text'])

# Function to change font
def change_font():
    font = font_combobox.get()
    corrected_text_label.config(font=(font, font_size_combobox.get()))

# Function to change character size
def change_character_size():
    font_size = font_size_combobox.get()
    corrected_text_label.config(font=(font_combobox.get(), font_size))

# Example usage:
text_to_analyze_str = tk.StringVar()
text_to_analyze_str.set("This is a sampple texxt forr word count analyssi.")

root = tk.Tk()
root.title("Barrier Breaker")

text_to_analyze = tk.Entry(root, textvariable=text_to_analyze_str)
text_to_analyze.pack(padx=20, pady=10)

language_combobox = ttk.Combobox(root, values=['en-US', 'fr', 'es'], state="readonly")
language_combobox.set('en-US')  # Default language
language_combobox.pack(padx=20, pady=10)
language_combobox.bind("<<ComboboxSelected>>", change_language)

analysis_result = analyze_text(text_to_analyze_str.get(), language_combobox.get())

flag_image = get_flag_image(language_combobox.get())
flag_image = flag_image.resize((200, 100), Image.ANTIALIAS)
flag_photo = ImageTk.PhotoImage(flag_image)

flag_label = tk.Label(root, image=flag_photo)
flag_label.image = flag_photo
flag_label.pack(padx=20, pady=10)

corrected_text_label = tk.Label(root, text=analysis_result['corrected_text'])
corrected_text_label.pack(padx=20, pady=5)

word_count_label = tk.Label(root, text=f"Word Count: {analysis_result['word_count']}")
word_count_label.pack(padx=20, pady=5)

highlighted_text_label = tk.Label(root, text=analysis_result['highlighted_text'])
highlighted_text_label.pack(padx=20, pady=5)

autocorrect_button = tk.Button(root, text="Autocorrect Mistakes", command=autocorrect_mistakes)
autocorrect_button.pack(padx=20, pady=10)

font_combobox = ttk.Combobox(root, values=['Arial', 'Times New Roman', 'Courier New'], state="readonly")
font_combobox.set('Arial')  # Default font
font_combobox.pack(padx=20, pady=5)

font_size_combobox = ttk.Combobox(root, values=['10', '12', '14', '16', '18', '20'], state="readonly")
font_size_combobox.set('12')  # Default font size
font_size_combobox.pack(padx=20, pady=5)

change_font_button = tk.Button(root, text="Change Font", command=change_font)
change_font_button.pack(padx=20, pady=5)

change_character_size_button = tk.Button(root, text="Change Character Size", command=change_character_size)
change_character_size_button.pack(padx=20, pady=5)

footer_label = tk.Label(root, text="Created by Blu Corbel", font=("Helvetica", 10))
footer_label.pack(padx=20, pady=10)

root.mainloop()
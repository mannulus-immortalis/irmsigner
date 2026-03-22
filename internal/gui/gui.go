package gui

import (
	"encoding/base64"
	"log"
	"time"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"github.com/mannulus-immortalis/irmsigner/internal/model"
)

const (
	COLUMN_SERIAL = iota
	COLUMN_THUMB
	COLUMN_SUBJ
	COLUMN_TILL
)

type gui struct {
	cfg        *model.Config
	mainWin    *gtk.Window
	listStore  *gtk.ListStore
	closeChan  chan bool
	icon       *gdk.Pixbuf
	onFileDrop model.FileDropFunc
}

func New(cfg *model.Config, closeChan chan bool) (*gui, error) {
	iconBytes, _ := base64.StdEncoding.DecodeString(model.AppIcon)
	icon, err := gdk.PixbufNewFromDataOnly(iconBytes)
	if err != nil {
		return nil, err
	}

	g := &gui{
		cfg:       cfg,
		closeChan: closeChan,
		icon:      icon,
	}

	err = g.start()
	if err != nil {
		return nil, err
	}

	return g, nil
}

func (g *gui) OnFileDrop(f model.FileDropFunc) {
	g.onFileDrop = f
}

func (g *gui) UpdateList(list []*model.Certificate) {
	g.listStore.Clear()
	time.Sleep(100 * time.Millisecond)
	if len(list) == 0 {
		_ = g.addRow([]interface{}{
			"!!!",
			"Please attach your cryptographic device",
			"!!!",
			"",
		})
		return
	}
	for _, c := range list {
		_ = g.addRow([]interface{}{
			c.SerialNumber,
			c.Thumbprint,
			c.IssuedTo,
			c.ValidTill.Format(time.DateOnly),
		})
	}
}

func (g *gui) RequestPass(certTitle string) string {
	passChan := make(chan string)

	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return ""
	}
	win.SetIcon(g.icon)

	label, _ := gtk.LabelNew(`IRMS portal requests your signature.
Please enter password for certificate:

` + certTitle)
	label.SetHExpand(true)
	label.SetHAlign(gtk.ALIGN_START)

	passwordEntry, _ := gtk.EntryNew()
	passwordEntry.SetVisibility(false)
	passwordEntry.SetPlaceholderText("Certificate password")
	passwordEntry.Connect("activate", func() {
		password, _ := passwordEntry.GetText()
		passChan <- password
		close(passChan)
		win.Close()
	})
	signBtn, _ := gtk.ButtonNewWithLabel("Sign")
	signBtn.Connect("clicked", func() {
		password, _ := passwordEntry.GetText()
		passChan <- password
		close(passChan)
		win.Close()
	})

	cancelBtn, _ := gtk.ButtonNewWithLabel("Cancel")
	cancelBtn.Connect("clicked", func() {
		close(passChan)
		win.Close()
	})

	img, err := gtk.ImageNewFromPixbuf(g.icon)
	if err != nil {
		return ""
	}

	grid, _ := gtk.GridNew()
	grid.SetBorderWidth(10)
	grid.SetColumnSpacing(10)
	grid.SetRowSpacing(10)
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	grid.SetOrientation(gtk.ORIENTATION_VERTICAL)
	grid.Attach(img, 0, 0, 1, 3)
	grid.Attach(label, 1, 0, 2, 1)
	grid.Attach(passwordEntry, 1, 1, 2, 1)
	grid.Attach(signBtn, 1, 2, 1, 1)
	grid.Attach(cancelBtn, 2, 2, 1, 1)

	win.Add(grid)

	win.SetModal(true)
	win.SetDefaultSize(250, 100)
	win.SetTitle("IRMSigner password")
	win.ShowAll()

	return <-passChan
}

func (g *gui) StartSpinner() (func(), error) {
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return nil, err
	}
	win.SetIcon(g.icon)

	label, _ := gtk.LabelNew(`Signing document...`)
	label.SetHExpand(true)
	label.SetHAlign(gtk.ALIGN_CENTER)

	spinner, _ := gtk.SpinnerNew()

	img, err := gtk.ImageNewFromPixbuf(g.icon)
	if err != nil {
		return nil, err
	}
	grid, _ := gtk.GridNew()
	grid.SetBorderWidth(10)
	grid.SetColumnSpacing(10)
	grid.SetRowSpacing(10)
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	grid.SetOrientation(gtk.ORIENTATION_VERTICAL)
	grid.Attach(img, 0, 0, 1, 2)
	grid.Attach(label, 1, 0, 1, 1)
	grid.Attach(spinner, 1, 1, 1, 1)

	win.Add(grid)

	win.SetModal(true)
	win.SetDefaultSize(250, 100)
	win.SetTitle("IRMSigner Wait...")
	win.ShowAll()

	spinner.Start()

	return func() {
		spinner.Stop()
		win.Close()
	}, nil
}

func (g *gui) Stop() {
	gtk.MainQuit()
}

func (g *gui) start() error {
	gtk.Init(nil)

	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return err
	}
	g.mainWin = win
	win.SetIcon(g.icon)
	win.SetTitle("IRMSigner " + model.Version)
	win.SetDefaultSize(250, 100)
	win.Connect("destroy", func() {
		close(g.closeChan)
		gtk.MainQuit()
	})

	label, _ := gtk.LabelNew(`This application signs documents from IRMS portal with your certificate.
You will be asked for a password when IRMS portal requests signature.
If you want to sign a PDF file manually, select certificate and drop file in this window.`)
	label.SetHExpand(true)
	label.SetHAlign(gtk.ALIGN_START)

	minBtn, _ := gtk.ButtonNewWithLabel("Hide window")
	minBtn.Connect("clicked", func() {
		win.Iconify()
	})

	closeBtn, _ := gtk.ButtonNewWithLabel("Close application")
	closeBtn.Connect("clicked", func() {
		win.Close()
	})

	treeView, listStore, err := setupTreeView()
	if err != nil {
		return err
	}
	g.listStore = listStore

	g.UpdateList(nil)

	img, err := gtk.ImageNewFromPixbuf(g.icon)
	if err != nil {
		return err
	}

	grid, _ := gtk.GridNew()
	grid.SetBorderWidth(10)
	grid.SetColumnSpacing(10)
	grid.SetRowSpacing(10)
	grid.SetHExpand(true)
	grid.SetVExpand(true)
	grid.SetOrientation(gtk.ORIENTATION_VERTICAL)
	grid.Attach(img, 0, 0, 1, 3)
	grid.Attach(label, 1, 0, 2, 1)
	grid.Attach(treeView, 1, 1, 2, 1)
	grid.Attach(minBtn, 1, 2, 1, 1)
	grid.Attach(closeBtn, 2, 2, 1, 1)

	// file drop
	t_uri, _ := gtk.TargetEntryNew("text/uri-list", gtk.TARGET_OTHER_APP, 0)
	grid.DragDestSet(gtk.DEST_DEFAULT_ALL, []gtk.TargetEntry{*t_uri}, gdk.ACTION_COPY)
	grid.Connect("drag-data-received", func(l *gtk.Grid, ctx *gdk.DragContext, x int, y int, data *gtk.SelectionData, info uint, time uint) {
		if g.onFileDrop != nil {
			certSerial := ""

			sel, err := treeView.GetSelection()
			if err != nil {
				log.Printf("GetSelection failed: %w", err)
				return
			}
			if sel.CountSelectedRows() != 1 {
				log.Printf("Unexpected selected rows count: %d", sel.CountSelectedRows())
				return
			}

			_, treeiter, ok := sel.GetSelected()
			if !ok || treeiter == nil {
				log.Printf("GetSelected failed")
				return
			}

			val, err := listStore.GetValue(treeiter, 0)
			if err != nil {
				log.Printf("GetValue failed: %w", err)
				return
			}

			certSerial, err = val.GetString()
			if err != nil {
				log.Printf("GetString failed: %w", err)
				return
			}

			go g.onFileDrop(string(data.GetData()), certSerial)
		}
	})

	win.Add(grid)
	win.ShowAll()
	// win.Iconify()
	go gtk.Main()
	return nil
}

// Add a column to the tree view (during the initialization of the tree view)
func createColumn(title string, id int) *gtk.TreeViewColumn {
	cellRenderer, err := gtk.CellRendererTextNew()
	if err != nil {
		log.Fatal("Unable to create text cell renderer:", err)
	}

	column, err := gtk.TreeViewColumnNewWithAttribute(title, cellRenderer, "text", id)
	if err != nil {
		log.Fatal("Unable to create cell column:", err)
	}

	return column
}

// Creates a tree view and the list store that holds its data
func setupTreeView() (*gtk.TreeView, *gtk.ListStore, error) {
	treeView, err := gtk.TreeViewNew()
	if err != nil {
		return nil, nil, err
	}

	treeView.AppendColumn(createColumn("Serial", COLUMN_SERIAL))
	treeView.AppendColumn(createColumn("Thumbprint", COLUMN_THUMB))
	treeView.AppendColumn(createColumn("Issued to", COLUMN_SUBJ))
	treeView.AppendColumn(createColumn("Valid till", COLUMN_TILL))

	// Creating a list store. This is what holds the data that will be shown on our tree view.
	listStore, err := gtk.ListStoreNew(glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING, glib.TYPE_STRING)
	if err != nil {
		return nil, nil, err
	}
	treeView.SetModel(listStore)

	return treeView, listStore, nil
}

// Append a row to the list store for the tree view
func (g *gui) addRow(cells []interface{}) error {
	if len(cells) != 4 {
		return model.ErrColumns
	}
	// Get an iterator for a new row at the end of the list store
	iter := g.listStore.Append()

	// Set the contents of the list store row that the iterator represents
	err := g.listStore.Set(iter,
		[]int{COLUMN_SERIAL, COLUMN_THUMB, COLUMN_SUBJ, COLUMN_TILL},
		cells)

	return err
}

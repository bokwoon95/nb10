package main

import (
	"bytes"
	"fmt"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

var mathKind = ast.NewNodeKind("math")

type mathNode struct {
	ast.BaseBlock
}

func (n *mathNode) Kind() ast.NodeKind {
	return mathKind
}

func (n *mathNode) Dump(source []byte, level int) {
	ast.DumpHelper(n, source, level, nil, nil)
}

type mathExtension struct{}

func (e *mathExtension) Extend(m goldmark.Markdown) {
	m.Parser().AddOptions(
		parser.WithASTTransformers(
			util.Prioritized(&mathTransformer{}, 100),
		),
	)
	m.Renderer().AddOptions(
		renderer.WithNodeRenderers(
			util.Prioritized(&mathRenderer{}, 1),
		),
	)
}

type mathTransformer struct{}

func (m *mathTransformer) Transform(doc *ast.Document, reader text.Reader, pc parser.Context) {
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if cb, ok := n.(*ast.FencedCodeBlock); ok && string(cb.Language(reader.Source())) == "math" {
			fmt.Println("got here!")
			mathNode := &mathNode{}
			mathNode.AppendChild(mathNode, cb)
			n.Parent().ReplaceChild(n.Parent(), n, mathNode)
		}
		return ast.WalkContinue, nil
	})
}

type mathRenderer struct{}

func (r *mathRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(mathKind, r.renderMath)
}

func (r *mathRenderer) renderMath(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	// TODO: what if I just overrode the renderer for fenced code blocks?
	fmt.Println("got here!!")
	if entering {
		w.WriteString("bruh")
		return ast.WalkContinue, nil
	}
	return ast.WalkContinue, nil
}

func main() {
	markdown := goldmark.New(
		goldmark.WithExtensions(&mathExtension{}),
	)

	source := []byte("Here's some math:\n\n```math\nx = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}\n``` ah be ce de\n")
	var buf bytes.Buffer
	if err := markdown.Convert(source, &buf); err != nil {
		panic(err)
	}
	fmt.Println(buf.String())
}


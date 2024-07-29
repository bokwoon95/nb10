package main

import (
	"bytes"
	"fmt"

	"github.com/bokwoon95/nb10/internal/markdownmath"
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
			util.Prioritized(&mathRenderer{}, 100),
		),
	)
}

type mathTransformer struct{}

func (m *mathTransformer) Transform(doc *ast.Document, reader text.Reader, pc parser.Context) {
	// var mathCodeBlocks []*ast.FencedCodeBlock
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if cb, ok := n.(*ast.FencedCodeBlock); ok && string(cb.Language(reader.Source())) == "math" {
			fmt.Println("got here!")
			// fmt.Println(string(reader.Source()))
			// segments := cb.Lines()
			// for i := 0; i < segments.Len(); i++ {
			// 	segment := segments.At(i)
			// 	fmt.Println(i, string(segment.Value(reader.Source())))
			// }
			mathNode := &mathNode{}
			mathNode.SetLines(cb.Lines())
			parent := cb.Parent()
			if parent != nil {
				parent.ReplaceChild(parent, cb, mathNode)
			}
		}
		return ast.WalkContinue, nil
	})
}

type mathRenderer struct{}

func (r *mathRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(mathKind, r.renderMath)
}

func (r *mathRenderer) renderMath(w util.BufWriter, source []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	fmt.Println("got here!!")
	if entering {
		w.WriteString("bruh")
		return ast.WalkContinue, nil
	}
	return ast.WalkContinue, nil
}

func main() {
	markdown := goldmark.New(
		goldmark.WithExtensions(markdownmath.Extension),
	)
	source := []byte("Here's some math:\n\n```math\nx = \\frac{-b \\pm \\sqrt{b^2 - 4ac}}{2a}\n```\n ah be ce de\n")

// 	node := markdown.Parser().Parse(text.NewReader(source))
// 	node.Dump(source, 1)
// 	if true {
// 		return
// 	}

	var buf bytes.Buffer
	if err := markdown.Convert(source, &buf); err != nil {
		panic(err)
	}
	fmt.Println(buf.String())
}


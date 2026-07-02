package slack

import (
	"context"
	"fmt"

	"github.com/slack-go/slack"
)

type botNotifier struct {
	client      *slack.Client
	channel     string
	disableFile bool
}

func newBotNotifier(token, channel string, disableFile bool) *botNotifier {
	return &botNotifier{
		client:      slack.New(token),
		channel:     channel,
		disableFile: disableFile,
	}
}

func (b *botNotifier) Notify(ctx context.Context, summary Summary, files []string) error {
	blocks := buildBlocks(summary, files, true)
	_, _, err := b.client.PostMessageContext(ctx, b.channel, slack.MsgOptionBlocks(convertBlocks(blocks)...))
	if err != nil {
		return fmt.Errorf("slack post message: %w", err)
	}

	if b.disableFile || len(files) == 0 {
		return nil
	}

	for _, path := range files {
		_, err := b.client.UploadFileContext(ctx, slack.UploadFileParameters{
			Channel:        b.channel,
			File:           path,
			Title:          path,
			InitialComment: "Scan report attached.",
		})
		if err != nil {
			return fmt.Errorf("slack upload %s: %w", path, err)
		}
	}

	return nil
}

func convertBlocks(blocks []slackBlock) []slack.Block {
	out := make([]slack.Block, 0, len(blocks))
	for _, b := range blocks {
		switch b.Type {
		case "header":
			if b.Text != nil {
				out = append(out, slack.NewHeaderBlock(
					slack.NewTextBlockObject(b.Text.Type, b.Text.Text, true, false),
				))
			}
		case "divider":
			out = append(out, slack.NewDividerBlock())
		case "section":
			var text *slack.TextBlockObject
			if b.Text != nil {
				text = slack.NewTextBlockObject(b.Text.Type, b.Text.Text, false, false)
			}
			out = append(out, slack.NewSectionBlock(text, convertFields(b.Fields), nil))
		}
	}
	return out
}

func convertFields(fields []slackText) []*slack.TextBlockObject {
	out := make([]*slack.TextBlockObject, 0, len(fields))
	for _, f := range fields {
		out = append(out, slack.NewTextBlockObject(f.Type, f.Text, false, false))
	}
	return out
}
